// Package secrets handles secret generation and management for sdbx.
package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/get-sdbx/sdbx/internal/securefs"
)

const maxSecretFileSize = 1 << 20

// #nosec G101 -- this constant names a managed file; it is not a credential value.
const CloudflaredTunnelTokenFile = "cloudflared_tunnel_token.txt"

var containerReadableSecretFiles = map[string]struct{}{
	ConsoleProxyCAFile:                    {},
	ConsoleProxyClientCertFile:            {},
	ConsoleProxyClientKeyFile:             {},
	"authelia_jwt_secret.txt":             {},
	"authelia_session_secret.txt":         {},
	"authelia_storage_encryption_key.txt": {},
	CloudflaredTunnelTokenFile:            {},
	"cobalt_keys.txt":                     {},
	"unpackerr_lidarr_api_key.txt":        {},
	"unpackerr_radarr_api_key.txt":        {},
	"unpackerr_sonarr_api_key.txt":        {},
	"unpackerr_whisparr_api_key.txt":      {},
}

// SecretFiles defines the secrets that sdbx manages
var SecretFiles = map[string]int{
	ConsoleProxyCAFile:                    0,
	ConsoleProxyServerCertFile:            0,
	ConsoleProxyServerKeyFile:             0,
	ConsoleProxyClientCertFile:            0,
	ConsoleProxyClientKeyFile:             0,
	"authelia_jwt_secret.txt":             64,
	"authelia_session_secret.txt":         64,
	"authelia_storage_encryption_key.txt": 64,
	CloudflaredTunnelTokenFile:            0, // User-provided
	"plex_claim_token.txt":                0, // User-provided
	// Admin passwords for services whose `sdbx integrate` post-init hook
	// authoritatively sets the password (mirrors qbittorrent_password.txt
	// pattern — generated lazily on first integrate, listed here so it
	// shows up in `sdbx secrets list`).
	"qbittorrent_password.txt":       24,
	"filebrowser_admin_password.txt": 24,
	"sonarr_admin_password.txt":      24,
	"prowlarr_admin_password.txt":    24,
	"radarr_admin_password.txt":      24,
	"lidarr_admin_password.txt":      24,
	"whisparr_admin_password.txt":    24,
	"qui_admin_password.txt":         24,
	"wizarr_admin_password.txt":      24,
	"cobalt_keys.txt":                0,
	"unpackerr_lidarr_api_key.txt":   0,
	"unpackerr_radarr_api_key.txt":   0,
	"unpackerr_sonarr_api_key.txt":   0,
	"unpackerr_whisparr_api_key.txt": 0,
}

// FileMode returns the protected host mode required by one managed secret.
//
// Docker Compose implements file-backed secrets as bind mounts, so non-root
// processes and capability-restricted Traefik cannot read mode-0600 sources
// owned by the project user. Their files are mode 0644 inside a mode-0700
// secrets directory:
// other host users still cannot traverse the parent, while the intended
// containers can read their single-file, read-only mounts. Doctor additionally
// verifies the private parent, matching ownership, and single-link invariant.
func FileMode(filename string) os.FileMode {
	if ContainerReadable(filename) {
		return 0o644
	}
	return 0o600
}

// ContainerReadable reports whether a managed file must be readable by a
// non-root or capability-restricted container through a file-backed secret mount.
func ContainerReadable(filename string) bool {
	_, ok := containerReadableSecretFiles[filename]
	return ok
}

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("secret length must be positive")
	}
	bytes := make([]byte, length)
	defer wipeSecretBytes(bytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// GenerateSecrets creates all required secret files
func GenerateSecrets(secretsDir string) error {
	return GenerateSelectedSecrets(secretsDir, SecretFiles)
}

// GenerateSelectedSecrets creates only the requested secret files. Existing
// values are preserved and permission-repaired. A zero length denotes a
// manual credential placeholder; positive lengths are generated securely.
func GenerateSelectedSecrets(secretsDir string, selected map[string]int) error {
	if err := securefs.EnsureDir(secretsDir, 0o700); err != nil {
		return fmt.Errorf("prepare secrets directory: %w", err)
	}

	filenames := make([]string, 0, len(selected))
	for filename := range selected {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)

	for _, filename := range filenames {
		length := selected[filename]
		if length < 0 || length > 4096 {
			return fmt.Errorf("invalid generated length %d for %s", length, filename)
		}
		path, err := managedSecretPath(secretsDir, filename)
		if err != nil {
			return err
		}

		info, err := os.Lstat(path)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("managed secret %s must be a regular file, not a symlink or special file", filename)
			}
			if err := os.Chmod(path, FileMode(filename)); err != nil {
				return fmt.Errorf("repair permissions for %s: %w", filename, err)
			}
			continue
		case !os.IsNotExist(err):
			return fmt.Errorf("inspect managed secret %s: %w", filename, err)
		}

		var contents []byte
		if length == 0 {
			contents = []byte{}
		} else {
			secret, err := GenerateRandomString(length)
			if err != nil {
				return err
			}
			contents = []byte(secret)
		}
		writeErr := securefs.WriteFileAtomic(
			path,
			contents,
			0o700,
			FileMode(filename),
		)
		wipeSecretBytes(contents)
		if writeErr != nil {
			return fmt.Errorf("failed to write %s: %w", filename, writeErr)
		}
	}

	return nil
}

// RepairExistingPermissions restores managed secret modes without creating or
// replacing values. It is safe to run immediately before Compose startup,
// including after a backup restore that conservatively wrote every secret as
// mode 0600.
func RepairExistingPermissions(secretsDir string) error {
	if err := securefs.EnsureDir(secretsDir, 0o700); err != nil {
		return fmt.Errorf("prepare secrets directory: %w", err)
	}
	for filename := range SecretFiles {
		path, err := managedSecretPath(secretsDir, filename)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		switch {
		case os.IsNotExist(err):
			continue
		case err != nil:
			return fmt.Errorf("inspect managed secret %s: %w", filename, err)
		case info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular():
			return fmt.Errorf(
				"managed secret %s must be a regular file, not a symlink or special file",
				filename,
			)
		}
		if err := os.Chmod(path, FileMode(filename)); err != nil {
			return fmt.Errorf("repair permissions for %s: %w", filename, err)
		}
	}
	return nil
}

// ReadSecret reads a secret from file
// Returns error if file is empty or contains only whitespace
func ReadSecret(secretsDir, name string) (string, error) {
	if _, err := managedSecretPath(secretsDir, name); err != nil {
		return "", err
	}
	data, err := readManagedSecret(secretsDir, name, false)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", name, err)
	}
	defer wipeSecretBytes(data)

	// Trim whitespace
	secret := strings.TrimSpace(string(data))

	// Check if empty
	if secret == "" {
		return "", &SecretNotConfiguredError{Filename: name}
	}

	return secret, nil
}

// ListSecrets returns all secret files and their status
func ListSecrets(secretsDir string) (map[string]bool, error) {
	result := make(map[string]bool)

	for filename := range SecretFiles {
		if _, err := managedSecretPath(secretsDir, filename); err != nil {
			return nil, err
		}
		data, err := securefs.ReadRegularFileAt(
			secretsDir,
			filename,
			maxSecretFileSize,
		)
		if err != nil {
			result[filename] = false
			continue
		}
		result[filename] = strings.TrimSpace(string(data)) != ""
		wipeSecretBytes(data)
	}

	return result, nil
}

func managedSecretPath(secretsDir, name string) (string, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return "", fmt.Errorf("invalid secret filename %q", name)
	}
	return filepath.Join(secretsDir, name), nil
}

func readManagedSecret(
	secretsDir, name string,
	allowEmpty bool,
) ([]byte, error) {
	data, err := securefs.ReadRegularFileAt(
		secretsDir,
		name,
		maxSecretFileSize,
	)
	if err != nil {
		return nil, err
	}
	if !allowEmpty && strings.TrimSpace(string(data)) == "" {
		return nil, &SecretNotConfiguredError{Filename: name}
	}
	return data, nil
}

func wipeSecretBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
