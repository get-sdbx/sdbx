package integrate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

// ArrKeyResult records what happened to a single *arr's API key during
// EnsureArrAPIKeys. It's surfaced to the user so they can see what was new.
type ArrKeyResult struct {
	Service string
	Action  string // "kept", "injected", "created"
	Reason  string // optional one-liner
	Err     error
}

// EnsureArrAPIKeys walks every enabled *arr service and guarantees that its
// host-side config.xml has an <ApiKey> element. Three outcomes per service:
//
//   - File missing — write a minimal config.xml with a fresh random key.
//     The *arr's first start will fill in the rest of the fields.
//   - File present, no <ApiKey> — inject a fresh random key inline,
//     preserving the rest of the document byte-for-byte.
//   - File present with an <ApiKey> — leave the file untouched. We treat
//     any persisted key as user-managed (it might have been customised via
//     the WebUI; overwriting would be hostile).
//
// All writes are atomic, chmod 0o600, and chown PUID:PGID. The owning
// linuxserver container can read the API key without exposing it to other host
// users. The function is safe to call on every
// `sdbx generate`; it only mutates files when something is missing.
func EnsureArrAPIKeys(cfg *config.Config) ([]ArrKeyResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}

	results := make([]ArrKeyResult, 0)
	configRoot := cfg.ConfigPath
	if configRoot == "" {
		configRoot = "./configs"
	}
	if err := securefs.EnsureDir(configRoot, 0o755); err != nil {
		return nil, fmt.Errorf("prepare *arr configuration root: %w", err)
	}
	for _, name := range EnabledArrs(cfg) {
		res := ArrKeyResult{Service: name}
		action, err := ensureArrConfigXMLAt(
			configRoot,
			filepath.Join(name, "config.xml"),
			cfg.PUID,
			cfg.PGID,
		)
		if err != nil {
			res.Err = err
			results = append(results, res)
			continue
		}
		res.Action = action
		results = append(results, res)
	}
	return results, nil
}

// ensureArrConfigXML applies the three-case logic described in EnsureArrAPIKeys
// and authoritatively enforces native Forms authentication for browser traffic.
//
// Authelia remains the public admin-only boundary, but it cannot protect direct
// requests from a compromised Docker-network peer. Forms + Enabled gives each
// *arr a second, application-owned boundary while preserving X-Api-Key access
// for explicitly configured integrations.
func ensureArrConfigXML(path string, uid, gid int) (action string, err error) {
	return ensureArrConfigXMLAt(
		filepath.Dir(path),
		filepath.Base(path),
		uid,
		gid,
	)
}

func ensureArrConfigXMLAt(
	configRoot string,
	name string,
	uid int,
	gid int,
) (action string, err error) {
	displayPath := filepath.Join(configRoot, name)
	if err := securefs.RepairRegularFileMetadataAt(
		configRoot,
		name,
		0o600,
		uid,
		gid,
	); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("repair metadata for %s: %w", displayPath, err)
	}

	data, err := securefs.ReadRegularFileAt(configRoot, name, maxManagedConfigSize)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read %s: %w", displayPath, err)
	}

	if errors.Is(err, os.ErrNotExist) {
		// Create from scratch with a minimal stub — the *arr will populate
		// the rest of the fields on first start.
		key, err := generateAPIKey()
		if err != nil {
			return "", err
		}
		stub := buildMinimalArrConfigXML(key)
		if err := writeArrFileChownAt(
			configRoot,
			name,
			[]byte(stub),
			0o600,
			uid,
			gid,
		); err != nil {
			return "", err
		}
		return "created", nil
	}

	mutated := false
	updated := data

	// Ensure exactly one ApiKey is present. Multiple keys are ambiguous because
	// upstream consumes only one of them; fail instead of guessing which value
	// is authoritative.
	apiKeyMatches := apiKeyRE.FindAll(updated, -1)
	if len(apiKeyMatches) > 1 {
		return "", fmt.Errorf("multiple <ApiKey> fields — refusing ambiguous configuration")
	}
	if len(apiKeyMatches) == 0 {
		key, err := generateAPIKey()
		if err != nil {
			return "", err
		}
		updated, err = injectAPIKey(updated, key)
		if err != nil {
			return "", err
		}
		mutated = true
	}

	for _, field := range []struct {
		name  string
		value string
		re    *regexp.Regexp
	}{
		{name: "AuthenticationMethod", value: "Forms", re: authMethodRE},
		{name: "AuthenticationRequired", value: "Enabled", re: authRequiredRE},
	} {
		var changed bool
		updated, changed, err = enforceSingleXMLField(
			updated,
			field.re,
			field.name,
			field.value,
		)
		if err != nil {
			return "", err
		}
		mutated = mutated || changed
	}

	if !mutated {
		return "kept", nil
	}
	if err := writeArrFileChownAt(
		configRoot,
		name,
		updated,
		0o600,
		uid,
		gid,
	); err != nil {
		return "", err
	}
	return "injected", nil
}

// authMethodRE matches one complete AuthenticationMethod element, including an
// empty value so enforceSingleXMLField never creates a duplicate beside it.
var authMethodRE = regexp.MustCompile(`(?s)<AuthenticationMethod>\s*[^<]*?\s*</AuthenticationMethod>`)

// authRequiredRE matches one complete AuthenticationRequired element.
var authRequiredRE = regexp.MustCompile(`(?s)<AuthenticationRequired>\s*[^<]*?\s*</AuthenticationRequired>`)

// enforceSingleXMLField inserts or replaces one security-owned field. Multiple
// occurrences are rejected because Servarr consumes the first occurrence and
// silently leaving an attacker-controlled duplicate would make the effective
// policy ordering-dependent.
func enforceSingleXMLField(
	data []byte,
	expression *regexp.Regexp,
	field, value string,
) ([]byte, bool, error) {
	matches := expression.FindAllIndex(data, -1)
	if len(matches) > 1 {
		return nil, false, fmt.Errorf(
			"multiple <%s> fields — refusing ambiguous configuration",
			field,
		)
	}
	canonical := []byte(fmt.Sprintf("<%s>%s</%s>", field, value, field))
	if len(matches) == 0 {
		updated, err := injectXMLField(data, field, value)
		return updated, err == nil, err
	}
	match := matches[0]
	if string(data[match[0]:match[1]]) == string(canonical) {
		return data, false, nil
	}
	out := make([]byte, 0, len(data)-match[1]+match[0]+len(canonical))
	out = append(out, data[:match[0]]...)
	out = append(out, canonical...)
	out = append(out, data[match[1]:]...)
	return out, true, nil
}

// injectXMLField inserts <Field>value</Field> just before </Config>, with the
// same byte-preserving guarantees as injectAPIKey.
func injectXMLField(data []byte, field, value string) ([]byte, error) {
	closeTag := []byte("</Config>")
	idx := lastIndex(data, closeTag)
	if idx < 0 {
		return nil, fmt.Errorf("no </Config> closing tag — refusing to mangle non-canonical file")
	}
	insertion := []byte(fmt.Sprintf("  <%s>%s</%s>\n", field, value, field))
	out := make([]byte, 0, len(data)+len(insertion))
	out = append(out, data[:idx]...)
	out = append(out, insertion...)
	out = append(out, data[idx:]...)
	return out, nil
}

// buildMinimalArrConfigXML returns the smallest valid config.xml that an
// *arr will accept on startup. The image's xmlstarlet entrypoint will fill
// in BindAddress/Port/etc. if absent.
func buildMinimalArrConfigXML(apiKey string) string {
	return fmt.Sprintf(`<Config>
  <ApiKey>%s</ApiKey>
  <AuthenticationMethod>Forms</AuthenticationMethod>
  <AuthenticationRequired>Enabled</AuthenticationRequired>
</Config>
`, apiKey)
}

// injectAPIKey inserts an <ApiKey>...</ApiKey> element into an existing
// config.xml just before the closing </Config> tag. Preserves all other
// content byte-for-byte, including line endings and indentation style.
func injectAPIKey(data []byte, apiKey string) ([]byte, error) {
	closeTag := []byte("</Config>")
	idx := lastIndex(data, closeTag)
	if idx < 0 {
		return nil, fmt.Errorf("no </Config> closing tag in config.xml — refusing to mangle non-canonical file")
	}
	insertion := []byte(fmt.Sprintf("  <ApiKey>%s</ApiKey>\n", apiKey))
	out := make([]byte, 0, len(data)+len(insertion))
	out = append(out, data[:idx]...)
	out = append(out, insertion...)
	out = append(out, data[idx:]...)
	return out, nil
}

// lastIndex returns the byte offset of the last occurrence of sep in data,
// or -1 if not found. (bytes.LastIndex is in stdlib but we avoid the import
// for the trivial helper since the rest of this file is import-light.)
func lastIndex(data, sep []byte) int {
	for i := len(data) - len(sep); i >= 0; i-- {
		match := true
		for j := range sep {
			if data[i+j] != sep[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// generateAPIKey returns a 32-character lowercase hex string suitable for
// use as an *arr <ApiKey>. Sourced from crypto/rand.
func generateAPIKey() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// writeFileChown writes data to path with the given mode and chowns it to
// uid:gid. Best-effort on chown — if the target UID doesn't exist locally
// (e.g. macOS dev machines), the file is still written successfully and
// the warning is left for the caller to surface.
func writeFileChown(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if err := securefs.WriteFileAtomicOwnedPreserveDir(
		path,
		data,
		0o755,
		mode.Perm(),
		uid,
		gid,
	); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeArrFileChownAt(
	configRoot string,
	name string,
	data []byte,
	mode os.FileMode,
	uid int,
	gid int,
) error {
	if err := securefs.WriteFileAtomicOwnedAt(
		configRoot,
		name,
		data,
		0o755,
		mode.Perm(),
		uid,
		gid,
	); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Join(configRoot, name), err)
	}
	return nil
}
