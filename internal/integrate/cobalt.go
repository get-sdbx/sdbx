package integrate

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

const cobaltKeysFilename = "cobalt_keys.txt"

var cobaltUUIDv4Pattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

// EnsureCobaltKeys preserves a valid operator-managed Cobalt key map or
// creates one random, rate-limited API key on first generation.
func EnsureCobaltKeys(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("nil config")
	}
	root := cfg.SecretsPath
	if root == "" {
		root = "./secrets"
	}
	if err := securefs.EnsureDir(root, 0o700); err != nil {
		return "", fmt.Errorf("prepare Cobalt secrets directory: %w", err)
	}
	path := filepath.Join(root, cobaltKeysFilename)
	data, err := securefs.ReadRegularFile(path, maxManagedConfigSize)
	switch {
	case err == nil && len(strings.TrimSpace(string(data))) > 0:
		defer wipeCredentialBytes(data)
		key, validateErr := ValidateCobaltKeys(data)
		if validateErr != nil {
			return "", fmt.Errorf("validate %s: %w", path, validateErr)
		}
		// #nosec G302 -- the private parent confines this bind-mounted, container-readable key map.
		if chmodErr := os.Chmod(path, 0o644); chmodErr != nil {
			return "", fmt.Errorf("repair %s permissions: %w", path, chmodErr)
		}
		return key, nil
	case err != nil && !os.IsNotExist(err):
		return "", fmt.Errorf("read %s: %w", path, err)
	}

	key, err := generateUUIDv4()
	if err != nil {
		return "", err
	}
	document := map[string]map[string]any{
		key: {
			"name":            "SDBX operator",
			"limit":           20,
			"allowedServices": "all",
		},
	}
	data, err = json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode Cobalt key map: %w", err)
	}
	data = append(data, '\n')
	defer wipeCredentialBytes(data)
	if err := securefs.WriteFileAtomic(path, data, 0o700, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return key, nil
}

// ValidateCobaltKeys validates a Cobalt key-map document and returns its first
// key in lexical order for deterministic operator recovery output.
func ValidateCobaltKeys(data []byte) (string, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}
	if len(document) == 0 {
		return "", fmt.Errorf("key map must contain at least one UUIDv4 key")
	}
	first := ""
	for key, settings := range document {
		if !cobaltUUIDv4Pattern.MatchString(key) {
			return "", fmt.Errorf("key %q is not a lowercase UUIDv4", key)
		}
		var object map[string]any
		if err := json.Unmarshal(settings, &object); err != nil || object == nil {
			return "", fmt.Errorf("settings for key %q must be a JSON object", key)
		}
		if first == "" || key < first {
			first = key
		}
	}
	return first, nil
}

func generateUUIDv4() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate Cobalt API key: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	), nil
}
