// Package licensegen generates the third-party notices distributed with SDBX.
package licensegen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const maxNoticeSize = 1 << 20

type module struct {
	Path    string  `json:"Path"`
	Version string  `json:"Version"`
	Dir     string  `json:"Dir"`
	Main    bool    `json:"Main"`
	Replace *module `json:"Replace"`
}

type packageRecord struct {
	ImportPath string  `json:"ImportPath"`
	Dir        string  `json:"Dir"`
	Standard   bool    `json:"Standard"`
	Module     *module `json:"Module"`
}

type noticeFile struct {
	Component string
	Path      string
	Content   []byte
}

// Generate returns deterministic third-party notices for both Linux release
// architectures and the Go standard library used to build the tool.
func Generate(ctx context.Context, repositoryRoot string) ([]byte, error) {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}

	files := make(map[string]noticeFile)
	for _, architecture := range []string{"amd64", "arm64"} {
		packages, err := listPackages(ctx, root, architecture)
		if err != nil {
			return nil, err
		}
		for _, pkg := range packages {
			if pkg.Standard || pkg.Module == nil || pkg.Module.Main {
				continue
			}
			moduleInfo := pkg.Module
			if moduleInfo.Replace != nil {
				moduleInfo = moduleInfo.Replace
			}
			if moduleInfo.Dir == "" {
				return nil, fmt.Errorf("package %s has no module directory", pkg.ImportPath)
			}
			paths, err := findLicenseFiles(pkg.Dir, moduleInfo.Dir)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", pkg.ImportPath, err)
			}
			component := pkg.Module.Path
			version := pkg.Module.Version
			if version != "" {
				component += " " + version
			}
			for _, path := range paths {
				relative, err := filepath.Rel(moduleInfo.Dir, path)
				if err != nil {
					return nil, fmt.Errorf("resolve license path for %s: %w", pkg.ImportPath, err)
				}
				content, err := readNotice(path)
				if err != nil {
					return nil, err
				}
				key := component + "\x00" + filepath.ToSlash(relative)
				files[key] = noticeFile{
					Component: component,
					Path:      filepath.ToSlash(relative),
					Content:   content,
				}
			}
		}
	}

	if err := addGoNotices(files); err != nil {
		return nil, err
	}
	return render(files), nil
}

func listPackages(
	ctx context.Context,
	repositoryRoot string,
	architecture string,
) ([]packageRecord, error) {
	// #nosec G204 -- the executable and package targets are fixed; architecture
	// comes from the closed release-architecture list in Generate.
	command := exec.CommandContext(
		ctx,
		"go",
		"list",
		"-deps",
		"-json",
		"./cmd/sdbx",
		"./cmd/sdbxd",
	)
	command.Dir = repositoryRoot
	command.Env = append(
		os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH="+architecture,
	)
	output, err := command.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf(
				"go list for linux/%s: %w: %s",
				architecture,
				err,
				strings.TrimSpace(string(exitErr.Stderr)),
			)
		}
		return nil, fmt.Errorf("go list for linux/%s: %w", architecture, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(output))
	var packages []packageRecord
	for decoder.More() {
		var pkg packageRecord
		if err := decoder.Decode(&pkg); err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		packages = append(packages, pkg)
	}
	return packages, nil
}

func findLicenseFiles(packageDir string, moduleDir string) ([]string, error) {
	packageDir, err := filepath.Abs(packageDir)
	if err != nil {
		return nil, fmt.Errorf("resolve package directory: %w", err)
	}
	moduleDir, err = filepath.Abs(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("resolve module directory: %w", err)
	}
	relative, err := filepath.Rel(moduleDir, packageDir)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("package directory escapes its module")
	}

	for current := packageDir; ; current = filepath.Dir(current) {
		entries, err := os.ReadDir(current)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", current, err)
		}
		var licenses []string
		var notices []string
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := strings.ToUpper(entry.Name())
			switch {
			case name == "LICENSE" || strings.HasPrefix(name, "LICENSE.") ||
				name == "COPYING" || strings.HasPrefix(name, "COPYING."):
				licenses = append(licenses, filepath.Join(current, entry.Name()))
			case name == "NOTICE" || strings.HasPrefix(name, "NOTICE."):
				notices = append(notices, filepath.Join(current, entry.Name()))
			}
		}
		if len(licenses) > 0 {
			paths := append(licenses, notices...)
			sort.Strings(paths)
			return paths, nil
		}
		if current == moduleDir {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil, fmt.Errorf("no license file found within module")
}

func addGoNotices(files map[string]noticeFile) error {
	component := "Go standard library " + runtime.Version()
	for _, name := range []string{"LICENSE", "PATENTS"} {
		path := filepath.Join(runtime.GOROOT(), name)
		content, err := readNotice(path)
		if err != nil {
			return fmt.Errorf("Go standard library %s: %w", name, err)
		}
		files[component+"\x00"+name] = noticeFile{
			Component: component,
			Path:      name,
			Content:   content,
		}
	}
	return nil
}

func readNotice(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxNoticeSize {
		return nil, fmt.Errorf("%s exceeds the notice size limit", path)
	}
	// #nosec G304 -- path is confined to a module directory reported by the Go
	// toolchain or to the current GOROOT.
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return bytes.TrimSpace(content), nil
}

func render(files map[string]noticeFile) []byte {
	keys := make([]string, 0, len(files))
	for key := range files {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var output bytes.Buffer
	output.WriteString("SDBX THIRD-PARTY SOFTWARE NOTICES\n")
	output.WriteString("Code generated by `go run ./cmd/sdbx-licensegen --write`; DO NOT EDIT.\n\n")
	output.WriteString(
		"SDBX includes compiled third-party software. The following license and " +
			"notice files are reproduced from the exact dependency versions used " +
			"by the Linux release binaries.\n",
	)
	for _, key := range keys {
		file := files[key]
		output.WriteString("\n")
		output.WriteString(strings.Repeat("=", 78))
		output.WriteString("\nComponent: ")
		output.WriteString(file.Component)
		output.WriteString("\nFile: ")
		output.WriteString(file.Path)
		output.WriteString("\n")
		output.WriteString(strings.Repeat("-", 78))
		output.WriteString("\n")
		output.Write(file.Content)
		output.WriteString("\n")
	}
	return output.Bytes()
}
