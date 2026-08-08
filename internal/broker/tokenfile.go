package broker

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/get-sdbx/sdbx/internal/securefs"
)

const (
	encodedStaticTokenBytes = 43
	maxTokenFileBytes       = encodedStaticTokenBytes + 1
)

type TokenFileOptions struct {
	Path string
	GID  *int
}

func EnsureTokenFile(options TokenFileOptions) (string, error) {
	if !filepath.IsAbs(options.Path) {
		return "", fmt.Errorf("broker token path must be absolute")
	}
	if options.GID != nil {
		if *options.GID < 0 {
			return "", fmt.Errorf("broker token group ID must be non-negative")
		}
		if os.Geteuid() != 0 {
			return "", fmt.Errorf("broker token group ownership requires root")
		}
	}
	path := filepath.Clean(options.Path)
	parentPath := filepath.Dir(path)
	name := filepath.Base(path)
	if err := ensureTokenDirectory(parentPath, options.GID); err != nil {
		return "", fmt.Errorf("prepare broker token directory: %w", err)
	}
	root, _, err := securefs.OpenVerifiedRoot(parentPath)
	if err != nil {
		return "", fmt.Errorf("pin broker token directory: %w", err)
	}
	defer root.Close()
	if _, err := root.Lstat(name); err == nil {
		return loadTokenFileAt(root, name, options.GID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect broker token: %w", err)
	}
	var raw [32]byte
	defer zeroBytes(raw[:])
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate broker token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	contents := []byte(token + "\n")
	defer zeroBytes(contents)
	if err := writeTokenFileExclusive(root, name, contents, options.GID); err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadTokenFileAt(root, name, options.GID)
		}
		return "", fmt.Errorf("write broker token: %w", err)
	}
	return token, nil
}

func LoadTokenFile(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("broker token path must be absolute")
	}
	path = filepath.Clean(path)
	root, _, err := securefs.OpenVerifiedRoot(filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("pin broker token directory: %w", err)
	}
	defer root.Close()
	return loadTokenFileAt(root, filepath.Base(path), nil)
}

func loadTokenFileAt(root *os.Root, name string, gid *int) (string, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return "", fmt.Errorf("inspect broker token: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("broker token must be a regular file, not a symlink or special file")
	}
	if info.Mode().Perm() != 0o640 {
		return "", fmt.Errorf("broker token file mode must be exactly 0640")
	}
	if info.Size() > maxTokenFileBytes {
		return "", fmt.Errorf("broker token exceeds the %d-byte read limit", maxTokenFileBytes)
	}
	file, err := root.Open(name)
	if err != nil {
		return "", fmt.Errorf("read broker token: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil ||
		!opened.Mode().IsRegular() ||
		opened.Mode().Perm() != 0o640 ||
		!os.SameFile(info, opened) {
		return "", fmt.Errorf("broker token changed while it was being opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxTokenFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("read broker token: %w", err)
	}
	if len(data) > maxTokenFileBytes {
		return "", fmt.Errorf("broker token exceeds the %d-byte read limit", maxTokenFileBytes)
	}
	defer zeroBytes(data)
	if len(data) != encodedStaticTokenBytes &&
		(len(data) != maxTokenFileBytes || data[encodedStaticTokenBytes] != '\n') {
		return "", fmt.Errorf(
			"broker token file must contain exactly one canonical token and an optional final newline",
		)
	}
	token := string(data[:encodedStaticTokenBytes])
	if _, err := NewStaticTokenAuthorizer(token); err != nil {
		return "", fmt.Errorf("invalid broker token file: %w", err)
	}
	if gid != nil {
		if err := file.Chown(0, *gid); err != nil {
			return "", fmt.Errorf("repair broker token ownership: %w", err)
		}
		if err := file.Sync(); err != nil {
			return "", fmt.Errorf("sync repaired broker token ownership: %w", err)
		}
		repaired, err := file.Stat()
		if err != nil ||
			!repaired.Mode().IsRegular() ||
			repaired.Mode().Perm() != 0o640 ||
			!os.SameFile(opened, repaired) {
			return "", fmt.Errorf("broker token changed while its ownership was being repaired")
		}
	}
	return token, nil
}

func ensureTokenDirectory(path string, gid *int) error {
	if err := securefs.EnsureDir(path, 0o750); err != nil {
		return err
	}
	root, _, err := securefs.OpenVerifiedRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Chmod(0o750); err != nil {
		return err
	}
	if gid != nil {
		uid := -1
		if os.Geteuid() == 0 {
			uid = 0
		}
		return directory.Chown(uid, *gid)
	}
	return nil
}

func writeTokenFileExclusive(
	root *os.Root,
	name string,
	data []byte,
	gid *int,
) (err error) {
	if root == nil {
		return fmt.Errorf("token directory root is required")
	}
	var random [12]byte
	defer zeroBytes(random[:])
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	tempName := "." + name + ".tmp-" + base64.RawURLEncoding.EncodeToString(random[:])
	temp, err := root.OpenFile(
		tempName,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return err
	}
	tempClosed := false
	defer func() {
		if !tempClosed {
			if closeErr := temp.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
				err = errors.Join(err, fmt.Errorf("close temporary token file: %w", closeErr))
			}
		}
		if removeErr := root.Remove(tempName); removeErr != nil &&
			!errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temporary token file: %w", removeErr))
		}
	}()
	if err = temp.Chmod(0o640); err != nil {
		return err
	}
	if gid != nil {
		if err = temp.Chown(-1, *gid); err != nil {
			return err
		}
	}
	if _, err = temp.Write(data); err != nil {
		return err
	}
	if err = temp.Sync(); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	tempClosed = true
	if err = root.Link(tempName, name); err != nil {
		return err
	}
	if err = root.Remove(tempName); err != nil {
		return fmt.Errorf("remove published token staging link: %w", err)
	}
	parent, err := root.Open(".")
	if err != nil {
		return err
	}
	parentClosed := false
	defer func() {
		if !parentClosed {
			if closeErr := parent.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
				err = errors.Join(err, fmt.Errorf("close token directory: %w", closeErr))
			}
		}
	}()
	if err = parent.Sync(); err != nil {
		return err
	}
	if err = parent.Close(); err != nil {
		return err
	}
	parentClosed = true
	return nil
}
