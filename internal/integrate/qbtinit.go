package integrate

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/get-sdbx/sdbx/internal/commandexec"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/redact"
	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

// QBTInitResult records what the qBT post-init step did.
type QBTInitResult struct {
	Action       string // "stamped", "rotated", "skipped-already-init", "skipped-not-enabled", "skipped-no-conf"
	PasswordSet  bool
	RestartedQBT bool
	Reason       string
	Err          error
}

const (
	qbtInitStampFilename = ".sdbx-init-stamp"
	// Version 5 keeps the security and peer-port migrations, serializes
	// WebUI\ServerDomains as a quoted QSettings string. Without the quotes,
	// semicolons are parsed as INI comments and Docker DNS aliases are lost,
	// and reconciles the public hostname resolved from the verified graph.
	qbtInitStampVersion = "5"

	// qbtPBKDF2Iterations is the iteration count qBittorrent itself uses
	// for WebUI\Password_PBKDF2. Hard-coded at 100000 in qBT source as of
	// v4.x and unchanged through v5.x. Verified against
	// src/base/utils/password.cpp.
	qbtPBKDF2Iterations = 100000
	qbtPBKDF2KeyLength  = 64 // bytes; SHA-512 output
	qbtPBKDF2SaltLength = 16 // bytes
)

// EnsureQBittorrentInitialised configures qBittorrent's WebUI for SDBX-style
// integration: it authoritatively sets a permanent admin password (sdbx
// generates the plaintext, hashes it with PBKDF2-HMAC-SHA512 the same way
// qBT does, and writes the result into qBittorrent.conf). Authentication is
// required for every caller, including loopback and Docker-network peers.
//
// Implementation note: this edits qBittorrent.conf directly while qBT is
// stopped, then restarts qBT to pick up the new conf. We can't drive the
// REST API from the host because in cloudflared mode qBT's port is not
// published — qBT runs in gluetun's network namespace. The conf-edit path
// has no such constraint and is what qBT will load on next start anyway.
//
// Idempotent: stamps <ConfigPath>/qbittorrent/.sdbx-init-stamp after success.
// The stamp is only a fast-path hint; the managed credential and qBittorrent
// configuration must still agree before a subsequent call can skip.
func EnsureQBittorrentInitialised(
	ctx context.Context,
	cfg *config.Config,
	publicHostname string,
) (*QBTInitResult, error) {
	return ensureQBittorrentInitialised(ctx, cfg, publicHostname, false)
}

// RotateQBittorrentCredential replaces the SDBX-managed qBittorrent password
// while qBittorrent is stopped, updates the recovery secret atomically, and
// rolls both files back on any write or restart failure.
func RotateQBittorrentCredential(
	ctx context.Context,
	cfg *config.Config,
	publicHostname string,
) (*QBTInitResult, error) {
	return ensureQBittorrentInitialised(ctx, cfg, publicHostname, true)
}

func ensureQBittorrentInitialised(
	ctx context.Context,
	cfg *config.Config,
	publicHostname string,
	rotate bool,
) (*QBTInitResult, error) {
	res := &QBTInitResult{}
	if !IsServiceEnabled(cfg, "qbittorrent") {
		res.Action = "skipped-not-enabled"
		return res, nil
	}

	stampPath := filepath.Join(cfg.ConfigPath, "qbittorrent", qbtInitStampFilename)
	confPath := qbtConfPath(cfg)
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		// Fresh deploy — qBT hasn't started yet, no conf to edit. The
		// stamp stays absent so a future `sdbx integrate` retries after
		// qBT has had a chance to write its initial conf.
		res.Action = "skipped-no-conf"
		res.Reason = fmt.Sprintf("qBittorrent.conf not present at %s — run `sdbx up`, wait for qBT to settle, then re-run `sdbx integrate`", confPath)
		return res, nil
	}
	credentialPath := secretsFilePath(cfg, "qbittorrent_password.txt")
	if !rotate && matchesStamp(stampPath, qbtInitStampVersion) {
		if qbtManagedCredentialMatches(confPath, credentialPath) {
			res.Action = "skipped-already-init"
			return res, nil
		}
		if err := writeStamp(
			stampPath,
			qbtInitStampVersion+"-credential-recovery-pending",
			cfg.PUID,
			cfg.PGID,
		); err != nil {
			res.Err = fmt.Errorf("mark qBT credential recovery pending: %w", err)
			return res, res.Err
		}
	}

	previousPassword := ""
	previousHash := ""
	password := ""
	var err error
	if rotate {
		previousPassword, err = sdbxsecrets.ReadSecret(
			filepath.Dir(credentialPath),
			filepath.Base(credentialPath),
		)
		if err != nil {
			res.Err = fmt.Errorf("read previous qBT password: %w", err)
			return res, res.Err
		}
		data, readErr := securefs.ReadRegularFile(confPath, maxManagedConfigSize)
		if readErr != nil {
			res.Err = fmt.Errorf("read qBittorrent.conf before rotation: %w", readErr)
			return res, res.Err
		}
		previousHash = qbtPreferenceValue(string(data), `WebUI\Password_PBKDF2`)
		wipeCredentialBytes(data)
		if !QBittorrentPasswordMatchesHash(previousPassword, previousHash) {
			res.Err = fmt.Errorf("refusing qBT rotation because the managed recovery credential does not match the persisted password")
			return res, res.Err
		}
		password, err = sdbxsecrets.GenerateRandomString(24)
	} else {
		password, err = readOrCreateSecret(credentialPath, 24, cfg.PUID, cfg.PGID)
	}
	if err != nil {
		res.Err = fmt.Errorf("provision qBT password: %w", err)
		return res, res.Err
	}

	hash, err := qbtPBKDF2Hash(password)
	if err != nil {
		res.Err = fmt.Errorf("hash qBT password: %w", err)
		return res, res.Err
	}

	// Stop qBT before editing the conf — qBT writes its in-memory state
	// to disk on graceful shutdown and would clobber our edit otherwise.
	if err := dockerComposeStop(ctx, "qbittorrent"); err != nil {
		res.Err = fmt.Errorf("stop qbittorrent: %w", err)
		return res, res.Err
	}
	res.RestartedQBT = true

	if err := updateQBTConfSections(
		confPath,
		map[string]map[string]string{
			"Preferences": qbtSecurityPreferences(publicHostname, hash),
			"BitTorrent": {
				`Session\Port`: strconv.Itoa(cfg.TorrentPort),
			},
		},
		cfg.PUID,
		cfg.PGID,
	); err != nil {
		_ = dockerComposeStart(ctx, "qbittorrent") // best-effort restart
		res.Err = fmt.Errorf("update qBittorrent.conf: %w", err)
		return res, res.Err
	}
	if rotate {
		credentialBytes := []byte(password)
		writeErr := writeFileChown(
			credentialPath,
			credentialBytes,
			0o600,
			cfg.PUID,
			cfg.PGID,
		)
		wipeCredentialBytes(credentialBytes)
		if writeErr != nil {
			rollbackErr := updateQBTConfSections(
				confPath,
				map[string]map[string]string{
					"Preferences": qbtSecurityPreferences(publicHostname, previousHash),
				},
				cfg.PUID,
				cfg.PGID,
			)
			_ = dockerComposeStart(ctx, "qbittorrent")
			res.Err = errors.Join(
				fmt.Errorf("persist rotated qBT credential: %w", writeErr),
				rollbackErr,
			)
			return res, res.Err
		}
	}
	res.PasswordSet = true

	if err := dockerComposeStart(ctx, "qbittorrent"); err != nil {
		if rotate {
			_ = updateQBTConfSections(
				confPath,
				map[string]map[string]string{
					"Preferences": qbtSecurityPreferences(publicHostname, previousHash),
				},
				cfg.PUID,
				cfg.PGID,
			)
			previousBytes := []byte(previousPassword)
			_ = writeFileChown(
				credentialPath,
				previousBytes,
				0o600,
				cfg.PUID,
				cfg.PGID,
			)
			wipeCredentialBytes(previousBytes)
			_ = dockerComposeStart(ctx, "qbittorrent")
		}
		res.Err = fmt.Errorf("start qbittorrent: %w", err)
		return res, res.Err
	}

	if err := writeStamp(stampPath, qbtInitStampVersion, cfg.PUID, cfg.PGID); err != nil {
		res.Err = fmt.Errorf("write stamp: %w", err)
		return res, res.Err
	}

	res.Action = "stamped"
	if rotate {
		res.Action = "rotated"
	}
	return res, nil
}

// qbtConfPath returns the host-side path to qBittorrent.conf. The
// linuxserver/qbittorrent image stores it at /config/qBittorrent/qBittorrent.conf,
// which maps to <ConfigPath>/qbittorrent/qBittorrent/qBittorrent.conf on the
// host.
func qbtConfPath(cfg *config.Config) string {
	return filepath.Join(cfg.ConfigPath, "qbittorrent", "qBittorrent", "qBittorrent.conf")
}

// qbtPBKDF2Hash returns the @ByteArray(salt:hash) string qBittorrent stores
// in WebUI\Password_PBKDF2. Salt is 16 bytes from crypto/rand, hash is
// PBKDF2-HMAC-SHA512(password, salt, 100000, 64).
func qbtPBKDF2Hash(password string) (string, error) {
	salt := make([]byte, qbtPBKDF2SaltLength)
	defer wipeCredentialBytes(salt)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	passwordBytes := []byte(password)
	defer wipeCredentialBytes(passwordBytes)
	derived := pbkdf2.Key(
		passwordBytes,
		salt,
		qbtPBKDF2Iterations,
		qbtPBKDF2KeyLength,
		sha512.New,
	)
	defer wipeCredentialBytes(derived)
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	hashB64 := base64.StdEncoding.EncodeToString(derived)
	return fmt.Sprintf("@ByteArray(%s:%s)", saltB64, hashB64), nil
}

func qbtManagedCredentialMatches(confPath, credentialPath string) bool {
	password, err := sdbxsecrets.ReadSecret(
		filepath.Dir(credentialPath),
		filepath.Base(credentialPath),
	)
	if err != nil {
		return false
	}
	data, err := securefs.ReadRegularFile(confPath, maxManagedConfigSize)
	if err != nil {
		return false
	}
	hash := qbtPreferenceValue(string(data), `WebUI\Password_PBKDF2`)
	return QBittorrentPasswordMatchesHash(password, hash)
}

func qbtPreferenceValue(contents, key string) string {
	inPreferences := false
	for _, line := range strings.Split(contents, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inPreferences = trimmed == "[Preferences]"
			continue
		}
		if !inPreferences {
			continue
		}
		candidate, value, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(candidate) == key {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// QBittorrentPasswordMatchesHash verifies an SDBX-managed plaintext credential
// against qBittorrent's persisted PBKDF2 representation without exposing
// either value.
func QBittorrentPasswordMatchesHash(password, encoded string) bool {
	const prefix = "@ByteArray("
	if !strings.HasPrefix(encoded, prefix) || !strings.HasSuffix(encoded, ")") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(encoded, prefix), ")"), ":")
	if len(parts) != 2 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil || len(salt) != qbtPBKDF2SaltLength {
		return false
	}
	defer wipeCredentialBytes(salt)
	expected, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(expected) != qbtPBKDF2KeyLength {
		return false
	}
	defer wipeCredentialBytes(expected)
	passwordBytes := []byte(password)
	defer wipeCredentialBytes(passwordBytes)
	actual := pbkdf2.Key(
		passwordBytes,
		salt,
		qbtPBKDF2Iterations,
		qbtPBKDF2KeyLength,
		sha512.New,
	)
	defer wipeCredentialBytes(actual)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// updateQBTConf rewrites qBittorrent.conf, ensuring every key in `set` is
// present with the given value. Keys not in the file are appended to the
// [Preferences] section (creating it if absent). All other lines are
// preserved verbatim. Output is chowned to uid:gid.
//
// qBT's INI dialect uses backslash-namespaced keys (e.g. WebUI\Password_PBKDF2)
// and escapes-as-literal-backslashes inside the file. We treat each set key
// literally — no transformation.
func updateQBTConf(path string, set map[string]string, uid, gid int) error {
	return updateQBTConfSections(
		path,
		map[string]map[string]string{"Preferences": set},
		uid,
		gid,
	)
}

// updateQBTConfSections rewrites explicitly named qBittorrent INI sections.
// Existing keys are replaced only inside their target section; missing
// sections and keys are created deterministically. Unmanaged content is
// preserved.
func updateQBTConfSections(
	path string,
	sections map[string]map[string]string,
	uid, gid int,
) error {
	data, err := securefs.ReadRegularFile(path, maxManagedConfigSize)
	if err != nil {
		return err
	}

	sectionNames := make([]string, 0, len(sections))
	for section := range sections {
		sectionNames = append(sectionNames, section)
	}
	sort.Strings(sectionNames)

	out := string(data)
	for _, section := range sectionNames {
		if section == "" || strings.ContainsAny(section, "[]\r\n") {
			return fmt.Errorf("invalid qBittorrent configuration section %q", section)
		}
		out = updateINISection(out, section, sections[section])
	}

	if err := writeFileChown(path, []byte(out), 0o600, uid, gid); err != nil {
		return err
	}
	return nil
}

func updateINISection(contents, section string, set map[string]string) string {
	lines := strings.Split(contents, "\n")
	header := "[" + section + "]"
	start := -1
	end := len(lines)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == header {
			start = i
			continue
		}
		if start >= 0 && i > start &&
			strings.HasPrefix(trimmed, "[") &&
			strings.HasSuffix(trimmed, "]") {
			end = i
			break
		}
	}

	if start < 0 {
		for len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		start = len(lines)
		lines = append(lines, header)
		end = len(lines)
	}

	written := make(map[string]bool, len(set))
	for i := start + 1; i < end; i++ {
		key, _, found := strings.Cut(lines[i], "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value, managed := set[key]
		if !managed {
			continue
		}
		lines[i] = key + "=" + value
		written[key] = true
	}

	missing := make([]string, 0, len(set))
	for key := range set {
		if key == "" || strings.ContainsAny(key, "=\r\n") {
			continue
		}
		if !written[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	insert := make([]string, 0, len(missing))
	for _, key := range missing {
		insert = append(insert, key+"="+set[key])
	}
	if len(insert) > 0 {
		lines = append(lines[:end], append(insert, lines[end:]...)...)
	}

	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
}

func qbtAllowedHostnames(publicHostname string) []string {
	hosts := []string{
		"localhost",
		"127.0.0.1",
		"sdbx-qbittorrent",
		"sdbx-gluetun",
	}
	if publicHostname != "" {
		hosts = append(hosts, publicHostname)
	}
	return hosts
}

func qbtSecurityPreferences(
	publicHostname string,
	passwordHash string,
) map[string]string {
	return map[string]string{
		`WebUI\Username`:                   "admin",
		`WebUI\Password_PBKDF2`:            passwordHash,
		`WebUI\LocalHostAuth`:              "true",
		`WebUI\AuthSubnetWhitelistEnabled`: "false",
		`WebUI\AuthSubnetWhitelist`:        "",
		`WebUI\HostHeaderValidation`:       "true",
		`WebUI\ServerDomains`:              strconv.Quote(strings.Join(qbtAllowedHostnames(publicHostname), ";")),
		`WebUI\CSRFProtection`:             "true",
		`WebUI\ClickjackingProtection`:     "true",
	}
}

// dockerComposeStop runs `docker compose stop <svc>` from the project dir.
// We rely on cwd being the project dir (cmd/sdbx/cmd/integrate.go chdirs
// into it before calling us).
func dockerComposeStop(ctx context.Context, svc string) error {
	out, err := commandexec.CombinedOutput(
		ctx,
		1<<20,
		nil,
		"docker",
		"compose",
		"stop",
		svc,
	)
	defer wipeCredentialBytes(out)
	if err != nil {
		return fmt.Errorf(
			"docker compose stop %s: %w (%s)",
			svc,
			err,
			redact.Text(strings.TrimSpace(string(out))),
		)
	}
	return nil
}

func dockerComposeStart(ctx context.Context, svc string) error {
	out, err := commandexec.CombinedOutput(
		ctx,
		1<<20,
		nil,
		"docker",
		"compose",
		"start",
		svc,
	)
	defer wipeCredentialBytes(out)
	if err != nil {
		return fmt.Errorf(
			"docker compose start %s: %w (%s)",
			svc,
			err,
			redact.Text(strings.TrimSpace(string(out))),
		)
	}
	return nil
}

// matchesStamp returns true if the stamp file at path exists and its content
// matches the given version.
func matchesStamp(path, version string) bool {
	data, err := securefs.ReadRegularFile(path, 256)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == version
}

func managedCredentialAvailable(cfg *config.Config, filename string) bool {
	path := secretsFilePath(cfg, filename)
	_, err := sdbxsecrets.ReadSecret(filepath.Dir(path), filepath.Base(path))
	return err == nil
}

func writeStamp(path, version string, uid, gid int) error {
	if err := securefs.EnsureDir(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeFileChown(path, []byte(version+"\n"), 0o600, uid, gid)
}

// readOrCreateSecret reads a secret file, generating + persisting one if
// missing. Returns the secret with whitespace trimmed.
func readOrCreateSecret(path string, length, uid, gid int) (string, error) {
	if err := securefs.EnsureDir(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	info, statErr := os.Lstat(path)
	switch {
	case statErr == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("managed credential must be a regular file")
		}
		secret, err := sdbxsecrets.ReadSecret(
			filepath.Dir(path),
			filepath.Base(path),
		)
		if err == nil {
			return secret, nil
		}
		if !sdbxsecrets.IsSecretNotConfigured(err) {
			return "", err
		}
	case !os.IsNotExist(statErr):
		return "", statErr
	}
	buf := make([]byte, length)
	defer wipeCredentialBytes(buf)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	pwd := strings.TrimRight(base64.URLEncoding.EncodeToString(buf), "=")
	if len(pwd) > length {
		pwd = pwd[:length]
	}
	contents := append([]byte(pwd), '\n')
	defer wipeCredentialBytes(contents)
	if err := writeFileChown(path, contents, 0o600, uid, gid); err != nil {
		return "", err
	}
	return pwd, nil
}
