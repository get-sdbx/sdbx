// Package doccheck validates checked-in documentation as executable release
// input. It checks internal links and anchors, fenced-block closure, shell
// syntax, and YAML/JSON parseability without executing documented commands.
package doccheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

var markdownLinkPattern = regexp.MustCompile(`!?\[[^\]]*\]\(([^)\s]+)(?:\s+["'][^"']*["'])?\)`)

type document struct {
	relative string
	absolute string
	lines    []string
	anchors  map[string]bool
}

// Check validates repository Markdown and returns every finding in stable
// path/line order.
func Check(root string) []error {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return []error{fmt.Errorf("resolve repository root: %w", err)}
	}
	documents, findings := loadDocuments(absoluteRoot)
	if len(documents) == 0 {
		findings = append(findings, errors.New("no Markdown documentation found"))
	}
	for _, document := range documents {
		findings = append(findings, checkFences(document)...)
		findings = append(findings, checkLinks(absoluteRoot, document, documents)...)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Error() < findings[j].Error()
	})
	return findings
}

func loadDocuments(root string) (map[string]*document, []error) {
	documents := make(map[string]*document)
	var findings []error
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return documents, []error{fmt.Errorf("open documentation root: %w", err)}
	}
	defer func() {
		_ = rootHandle.Close()
	}()
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			findings = append(findings, walkErr)
			return nil
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".test", "bin", "dist", "node_modules", "output", "test-artefacts":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			findings = append(findings, err)
			return nil
		}
		data, err := rootHandle.ReadFile(relative)
		if err != nil {
			findings = append(findings, fmt.Errorf("%s: read: %w", filepath.ToSlash(relative), err))
			return nil
		}
		relative = filepath.ToSlash(relative)
		lines := splitLines(string(data))
		documents[relative] = &document{
			relative: relative,
			absolute: path,
			lines:    lines,
			anchors:  markdownAnchors(lines),
		}
		return nil
	})
	if err != nil {
		findings = append(findings, err)
	}
	return documents, findings
}

func splitLines(value string) []string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.TrimSuffix(value, "\n")
	if value == "" {
		return []string{}
	}
	return strings.Split(value, "\n")
}

func markdownAnchors(lines []string) map[string]bool {
	anchors := make(map[string]bool)
	counts := make(map[string]int)
	inFence := false
	var fence byte
	var fenceLength int
	for _, line := range lines {
		if marker, length, _, ok := fenceStart(line); ok {
			if !inFence {
				inFence = true
				fence = marker
				fenceLength = length
			} else if marker == fence && length >= fenceLength {
				inFence = false
			}
			continue
		}
		if inFence {
			continue
		}
		trimmed := strings.TrimSpace(line)
		level := 0
		for level < len(trimmed) && trimmed[level] == '#' {
			level++
		}
		if level == 0 || level > 6 || level >= len(trimmed) || trimmed[level] != ' ' {
			continue
		}
		title := strings.TrimSpace(trimmed[level:])
		base := githubAnchor(title)
		if base == "" {
			continue
		}
		anchor := base
		if count := counts[base]; count > 0 {
			anchor = fmt.Sprintf("%s-%d", base, count)
		}
		counts[base]++
		anchors[anchor] = true
	}
	return anchors
}

func githubAnchor(title string) string {
	title = strings.ToLower(stripInlineMarkdown(title))
	var output strings.Builder
	lastSpace := false
	for _, character := range title {
		switch {
		case unicode.IsLetter(character), unicode.IsNumber(character):
			output.WriteRune(character)
			lastSpace = false
		case character == '-' || character == '_':
			output.WriteRune(character)
			lastSpace = false
		case unicode.IsSpace(character):
			if !lastSpace {
				output.WriteByte('-')
				lastSpace = true
			}
		}
	}
	return strings.Trim(output.String(), "-")
}

func stripInlineMarkdown(value string) string {
	replacer := strings.NewReplacer(
		"`", "",
		"*", "",
		"~", "",
		"[", "",
		"]", "",
	)
	return replacer.Replace(value)
}

func checkFences(document *document) []error {
	var findings []error
	var body bytes.Buffer
	inFence := false
	var marker byte
	var markerLength int
	var language string
	var startLine int

	for index, line := range document.lines {
		foundMarker, length, info, isMarker := fenceStart(line)
		if !inFence {
			if !isMarker {
				continue
			}
			inFence = true
			marker = foundMarker
			markerLength = length
			language = normalizeFenceLanguage(info)
			startLine = index + 1
			body.Reset()
			continue
		}
		if isMarker && foundMarker == marker && length >= markerLength &&
			strings.TrimSpace(info) == "" {
			findings = append(
				findings,
				validateFence(document.relative, startLine, language, body.String())...,
			)
			inFence = false
			continue
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	if inFence {
		findings = append(findings, fmt.Errorf(
			"%s:%d: unclosed %c fence",
			document.relative,
			startLine,
			marker,
		))
	}
	return findings
}

func fenceStart(line string) (byte, int, string, bool) {
	trimmed := strings.TrimLeft(line, " ")
	if len(line)-len(trimmed) > 3 || len(trimmed) < 3 {
		return 0, 0, "", false
	}
	marker := trimmed[0]
	if marker != '`' && marker != '~' {
		return 0, 0, "", false
	}
	length := 0
	for length < len(trimmed) && trimmed[length] == marker {
		length++
	}
	if length < 3 {
		return 0, 0, "", false
	}
	return marker, length, strings.TrimSpace(trimmed[length:]), true
}

func normalizeFenceLanguage(info string) string {
	info = strings.TrimSpace(info)
	if field := strings.Fields(info); len(field) > 0 {
		info = field[0]
	}
	info = strings.TrimPrefix(info, "{.")
	info = strings.TrimSuffix(info, "}")
	return strings.ToLower(info)
}

func validateFence(relative string, line int, language, body string) []error {
	switch language {
	case "bash", "sh", "shell":
		command := exec.Command("bash", "-n")
		command.Stdin = strings.NewReader(body)
		output, err := command.CombinedOutput()
		if err != nil {
			return []error{fmt.Errorf(
				"%s:%d: invalid shell fence: %s",
				relative,
				line,
				strings.TrimSpace(string(output)),
			)}
		}
	case "yaml", "yml":
		decoder := yaml.NewDecoder(strings.NewReader(body))
		for {
			var value any
			err := decoder.Decode(&value)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return []error{fmt.Errorf(
					"%s:%d: invalid YAML fence: %v",
					relative,
					line,
					err,
				)}
			}
		}
	case "json":
		decoder := json.NewDecoder(strings.NewReader(body))
		var value any
		if err := decoder.Decode(&value); err != nil {
			return []error{fmt.Errorf(
				"%s:%d: invalid JSON fence: %v",
				relative,
				line,
				err,
			)}
		}
		if err := decoder.Decode(&value); !errors.Is(err, io.EOF) {
			if err == nil {
				return []error{fmt.Errorf("%s:%d: JSON fence has trailing values", relative, line)}
			}
			return []error{fmt.Errorf(
				"%s:%d: invalid JSON fence trailing data: %v",
				relative,
				line,
				err,
			)}
		}
	}
	return nil
}

func checkLinks(
	root string,
	source *document,
	documents map[string]*document,
) []error {
	var findings []error
	for index, line := range source.lines {
		matches := markdownLinkPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			target := strings.Trim(match[1], "<>")
			if target == "" || externalLink(target) {
				continue
			}
			pathPart, anchorPart, _ := strings.Cut(target, "#")
			decodedPath, err := url.PathUnescape(pathPart)
			if err != nil {
				findings = append(findings, fmt.Errorf(
					"%s:%d: invalid link escape %q",
					source.relative,
					index+1,
					target,
				))
				continue
			}
			destinationPath := source.absolute
			if decodedPath != "" {
				if strings.HasPrefix(decodedPath, "/") {
					destinationPath = filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(decodedPath, "/")))
				} else {
					destinationPath = filepath.Join(filepath.Dir(source.absolute), filepath.FromSlash(decodedPath))
				}
			}
			destinationPath = filepath.Clean(destinationPath)
			relative, err := filepath.Rel(root, destinationPath)
			if err != nil || relative == ".." ||
				strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				findings = append(findings, fmt.Errorf(
					"%s:%d: internal link escapes repository: %s",
					source.relative,
					index+1,
					target,
				))
				continue
			}
			info, err := os.Stat(destinationPath)
			if err != nil {
				findings = append(findings, fmt.Errorf(
					"%s:%d: missing internal link target: %s",
					source.relative,
					index+1,
					target,
				))
				continue
			}
			if anchorPart == "" || info.IsDir() {
				continue
			}
			destinationRelative := filepath.ToSlash(relative)
			destination := documents[destinationRelative]
			if destination == nil {
				continue
			}
			anchor, err := url.PathUnescape(anchorPart)
			if err != nil || !destination.anchors[strings.ToLower(anchor)] {
				findings = append(findings, fmt.Errorf(
					"%s:%d: missing internal anchor: %s",
					source.relative,
					index+1,
					target,
				))
			}
		}
	}
	return findings
}

func externalLink(target string) bool {
	if strings.HasPrefix(target, "//") {
		return true
	}
	parsed, err := url.Parse(target)
	return err == nil && parsed.Scheme != ""
}

// Format renders findings for a command-line failure.
func Format(findings []error) string {
	if len(findings) == 0 {
		return ""
	}
	var output strings.Builder
	writer := bufio.NewWriter(&output)
	for _, finding := range findings {
		_, _ = fmt.Fprintf(writer, "- %v\n", finding)
	}
	_ = writer.Flush()
	return output.String()
}
