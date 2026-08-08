// Package redact removes common credential shapes from operator-visible text.
//
// Redaction is deliberately applied at output boundaries as well as close to
// subprocesses. It is a last line of defence for logs and diagnostics, not a
// substitute for keeping secrets out of errors in the first place.
package redact

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
)

const (
	Replacement          = "[REDACTED]"
	maxBufferedLineBytes = 2 << 20
	// #nosec G101 -- this is a regular-expression vocabulary of sensitive
	// field names, never a credential value.
	credentialName = `[a-z0-9_.-]*(?:password|passwd|passphrase|token|secret|identity|api[_-]?key|apikey|x-api-key|client[_-]?secret|access[_-]?token|refresh[_-]?token|private[_-]?key|claim|cookie)[a-z0-9_.-]*`
)

var (
	privateKeyBlock = regexp.MustCompile(
		`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`,
	)
	ageSecretKey       = regexp.MustCompile(`\bAGE-SECRET-KEY-1[0-9A-Z]+\b`)
	authorizationValue = regexp.MustCompile(
		`(?i)\b(Bearer|Basic)([ \t]+)[A-Za-z0-9._~+/=-]+`,
	)
	sensitiveHeader = regexp.MustCompile(
		`(?im)^([ \t]*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)[ \t]*:[ \t]*).*$`,
	)
	urlUserInfo = regexp.MustCompile(
		`(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@`,
	)
	sensitiveQuery = regexp.MustCompile(
		`(?i)([?&](?:password|passwd|passphrase|token|secret|api[_-]?key|apikey|client[_-]?secret|access[_-]?token|refresh[_-]?token)=)[^&#\s]+`,
	)
	qbittorrentTemporaryPassword = regexp.MustCompile(
		`(?i)(temporary password is provided for this session:[ \t]*)(\S+)`,
	)
	fileBrowserGeneratedPassword = regexp.MustCompile(
		`(?i)(initialized with randomly generated password:[ \t]*)(\S+)`,
	)
	xmlSecret = regexp.MustCompile(
		`(?is)(<(?:password|passwd|passphrase|token|secret|api[_-]?key|apikey|client[_-]?secret|access[_-]?token|refresh[_-]?token|private[_-]?key)>).*?(</(?:password|passwd|passphrase|token|secret|api[_-]?key|apikey|client[_-]?secret|access[_-]?token|refresh[_-]?token|private[_-]?key)>)`,
	)
	quotedAssignment = regexp.MustCompile(
		`(?i)(\b` + credentialName + `"?[ \t]*[:=][ \t]*)(["'])([^"'\r\n]*)(["'])`,
	)
	unquotedAssignment = regexp.MustCompile(
		`(?i)(\b` + credentialName + `"?[ \t]*[:=][ \t]*)([^\s,;]+)`,
	)
	credentialFlag = regexp.MustCompile(
		`(?i)(--` + credentialName + `(?:=|[ \t]+))("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`,
	)
)

// Text returns value with common secret-bearing shapes replaced. Go's regular
// expression engine is linear-time, so untrusted container logs cannot trigger
// catastrophic backtracking.
func Text(value string) string {
	if value == "" {
		return ""
	}
	value = privateKeyBlock.ReplaceAllString(value, "[REDACTED PRIVATE KEY]")
	value = ageSecretKey.ReplaceAllString(value, Replacement)
	value = sensitiveHeader.ReplaceAllString(value, "${1}"+Replacement)
	value = authorizationValue.ReplaceAllString(value, "${1}${2}"+Replacement)
	value = urlUserInfo.ReplaceAllString(value, "${1}"+Replacement+"@")
	value = sensitiveQuery.ReplaceAllString(value, "${1}"+Replacement)
	value = qbittorrentTemporaryPassword.ReplaceAllString(value, "${1}"+Replacement)
	value = fileBrowserGeneratedPassword.ReplaceAllString(value, "${1}"+Replacement)
	value = xmlSecret.ReplaceAllString(value, "${1}"+Replacement+"${2}")
	value = quotedAssignment.ReplaceAllString(value, "${1}${2}"+Replacement+"${4}")
	value = unquotedAssignment.ReplaceAllString(value, "${1}"+Replacement)
	return credentialFlag.ReplaceAllString(value, "${1}"+Replacement)
}

// Values also removes exact sensitive values known to the caller. It is useful
// only as defense in depth; credential-bearing subprocess or HTTP bodies
// should still be omitted from errors.
func Values(value string, sensitiveValues ...string) string {
	for _, sensitive := range sensitiveValues {
		if sensitive != "" {
			value = strings.ReplaceAll(value, sensitive, Replacement)
		}
	}
	return Text(value)
}

// LineWriter redacts complete lines before forwarding them. It is suitable for
// long-running subprocess output where credentials may be split across Write
// calls. An oversized line is replaced wholesale instead of risking disclosure
// or unbounded memory use.
type LineWriter struct {
	mu          sync.Mutex
	destination io.Writer
	pending     []byte
	discarding  bool
	closed      bool
}

// NewLineWriter returns a bounded redacting writer.
func NewLineWriter(destination io.Writer) *LineWriter {
	return &LineWriter{destination: destination}
}

func (w *LineWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, fmt.Errorf("redacting log writer is closed")
	}
	if w.destination == nil {
		return 0, fmt.Errorf("redacting log writer has no destination")
	}

	accepted := len(data)
	for len(data) > 0 {
		if w.discarding {
			newline := bytes.IndexByte(data, '\n')
			if newline < 0 {
				return accepted, nil
			}
			data = data[newline+1:]
			w.discarding = false
			continue
		}

		newline := bytes.IndexByte(data, '\n')
		if newline < 0 {
			if len(w.pending)+len(data) > maxBufferedLineBytes {
				w.pending = nil
				w.discarding = true
				if _, err := io.WriteString(
					w.destination,
					"[REDACTED OVERSIZED LOG LINE]\n",
				); err != nil {
					return 0, err
				}
				return accepted, nil
			}
			w.pending = append(w.pending, data...)
			return accepted, nil
		}

		line := append(w.pending, data[:newline]...)
		w.pending = nil
		data = data[newline+1:]
		if len(line) > maxBufferedLineBytes {
			if _, err := io.WriteString(
				w.destination,
				"[REDACTED OVERSIZED LOG LINE]\n",
			); err != nil {
				return 0, err
			}
			continue
		}
		if _, err := io.WriteString(w.destination, Text(string(line))+"\n"); err != nil {
			return 0, err
		}
	}
	return accepted, nil
}

// Close flushes a final unterminated line after redaction.
func (w *LineWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.destination == nil {
		return fmt.Errorf("redacting log writer has no destination")
	}
	if w.discarding || len(w.pending) == 0 {
		w.pending = nil
		return nil
	}
	pending := strings.Clone(Text(string(w.pending)))
	w.pending = nil
	_, err := io.WriteString(w.destination, pending)
	return err
}
