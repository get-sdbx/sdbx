package integrate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/securefs"
	"gopkg.in/yaml.v3"
)

const (
	janitorrConfigName   = "janitorr/application.yml"
	janitorrContainerUID = 1002
	janitorrContainerGID = 1001
)

// JanitorrConfigResult reports the non-secret outcome of a managed config
// reconciliation.
type JanitorrConfigResult struct {
	Action string
	Reason string
}

// ReconcileJanitorrConfig refreshes internal Arr endpoints and API keys in an
// existing SDBX-managed Janitorr configuration. Operator policy is preserved,
// and removing the first-line managed marker opts the file out byte-for-byte.
func ReconcileJanitorrConfig(
	cfg *config.Config,
	graph *registry.ResolutionGraph,
	dryRun bool,
) (*JanitorrConfigResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if !IsServiceEnabled(cfg, "janitorr") {
		return nil, nil
	}
	configRoot := cfg.ConfigPath
	if configRoot == "" {
		configRoot = "./configs"
	}
	data, err := securefs.ReadRegularFileAt(
		configRoot,
		janitorrConfigName,
		maxManagedConfigSize,
	)
	if errors.Is(err, os.ErrNotExist) {
		return &JanitorrConfigResult{
			Action: "skipped",
			Reason: "managed configuration is absent",
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Janitorr managed config: %w", err)
	}
	markerEnd := bytes.IndexByte(data, '\n')
	markerLine := ""
	if markerEnd >= 0 {
		markerLine = string(data[:markerEnd])
	}
	if markerLine != "# managed-by: sdbx" &&
		markerLine != "# managed-by: sdbx-generate" {
		return &JanitorrConfigResult{
			Action: "skipped",
			Reason: "managed-by marker is absent; operator-owned file was not modified",
		}, nil
	}
	managedMarker := append([]byte(nil), data[:markerEnd+1]...)

	var document yaml.Node
	if err := yaml.Unmarshal(
		data[markerEnd+1:],
		&document,
	); err != nil {
		return nil, fmt.Errorf("parse Janitorr managed config: %w", err)
	}
	root, err := documentMapping(&document)
	if err != nil {
		return nil, fmt.Errorf("parse Janitorr managed config: %w", err)
	}
	clients, err := ensureMappingValue(root, "clients")
	if err != nil {
		return nil, fmt.Errorf("reconcile Janitorr clients: %w", err)
	}
	for _, name := range []string{"sonarr", "radarr", "lidarr", "whisparr"} {
		if !IsServiceEnabled(cfg, name) {
			continue
		}
		apiKey, keyErr := ReadArrAPIKey(cfg, name)
		if keyErr != nil {
			return nil, fmt.Errorf("read %s API key for Janitorr: %w", name, keyErr)
		}
		if apiKey == "" {
			return nil, fmt.Errorf("%s API key is unavailable for Janitorr", name)
		}
		serviceURL, urlErr := StableArrServiceURL(cfg, graph, name)
		if urlErr != nil {
			return nil, fmt.Errorf("resolve %s URL for Janitorr: %w", name, urlErr)
		}
		client, clientErr := ensureMappingValue(clients, name)
		if clientErr != nil {
			return nil, fmt.Errorf("reconcile Janitorr %s client: %w", name, clientErr)
		}
		setScalar(client, "url", serviceURL, "!!str")
		setScalar(client, "api-key", apiKey, "!!str")
	}

	rendered, err := yaml.Marshal(&document)
	if err != nil {
		return nil, fmt.Errorf("render Janitorr managed config: %w", err)
	}
	rendered = append(managedMarker, rendered...)
	defer wipeCredentialBytes(rendered)
	action := "updated"
	if bytes.Equal(data, rendered) {
		action = "kept"
	}
	if dryRun {
		if action == "kept" {
			return &JanitorrConfigResult{Action: action}, nil
		}
		return &JanitorrConfigResult{
			Action: "would_" + action,
			Reason: "dry run; managed config was not written",
		}, nil
	}
	if action == "kept" {
		return &JanitorrConfigResult{Action: action}, nil
	}
	if err := securefs.WriteFileAtomicOwnedAt(
		configRoot,
		janitorrConfigName,
		rendered,
		0o755,
		0o600,
		janitorrContainerUID,
		janitorrContainerGID,
	); err != nil {
		return nil, fmt.Errorf("write Janitorr managed config: %w", err)
	}
	return &JanitorrConfigResult{Action: action}, nil
}

func janitorrConfigPath(cfg *config.Config) string {
	root := cfg.ConfigPath
	if root == "" {
		root = "./configs"
	}
	return filepath.Join(root, filepath.FromSlash(janitorrConfigName))
}
