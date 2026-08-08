package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/get-sdbx/sdbx/internal/securefs"
	"golang.org/x/term"
)

const maxCredentialBytes = 4096

func readPrivateCredentialFile(path, label string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s file: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s file must be a regular file, not a symlink", label)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s file permissions must be 0600 or stricter", label)
	}
	data, err := securefs.ReadRegularFile(path, maxCredentialBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", label, err)
	}
	return normalizeCredentialLine(data, label)
}

func readCredentialStdin(label string) ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf(
			"refusing echoed %s input from a terminal; use the wizard or pipe a single line to stdin",
			label,
		)
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxCredentialBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s from stdin: %w", label, err)
	}
	if len(data) > maxCredentialBytes {
		zeroBytes(data)
		return nil, fmt.Errorf("%s input exceeds %d bytes", label, maxCredentialBytes)
	}
	return normalizeCredentialLine(data, label)
}

func normalizeCredentialLine(data []byte, label string) ([]byte, error) {
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", label)
	}
	if bytes.ContainsAny(data, "\r\n\x00") {
		zeroBytes(data)
		return nil, fmt.Errorf("%s must contain exactly one line", label)
	}
	if !bytes.Equal(bytes.TrimSpace(data), data) {
		zeroBytes(data)
		return nil, fmt.Errorf("%s must not have leading or trailing whitespace", label)
	}
	return data, nil
}
