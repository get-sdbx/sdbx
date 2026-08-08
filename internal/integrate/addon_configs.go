package integrate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
	"github.com/get-sdbx/sdbx/internal/securefs"
	"gopkg.in/yaml.v3"
)

const (
	recyclarrConfigName  = "recyclarr/recyclarr.yml"
	qbitManageConfigName = "qbit-manage/config.yml"
	addonManagedMarker   = "# managed-by: sdbx\n"
)

type AddonConfigResult struct {
	Action string
	Reason string
}

// ReconcileRecyclarrConfig wires enabled Arr instances while preserving all
// operator-selected templates and quality policy. It adopts only Recyclarr's
// unmistakable empty starter; any other unmarked file is operator-owned.
func ReconcileRecyclarrConfig(
	cfg *config.Config,
	graph *registry.ResolutionGraph,
	dryRun bool,
) (*AddonConfigResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if !IsServiceEnabled(cfg, "recyclarr") {
		return nil, nil
	}
	data, err := readManagedAddonConfig(cfg, recyclarrConfigName)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return nil, fmt.Errorf("read Recyclarr config: %w", err)
	}
	marked := bytes.HasPrefix(data, []byte(addonManagedMarker))
	starter := bytes.Contains(data, []byte("An empty starter config")) &&
		bytes.Contains(data, []byte("This file WILL NOT WORK"))
	if !missing && !marked && !starter {
		return &AddonConfigResult{
			Action: "skipped",
			Reason: "managed-by marker is absent; operator-owned file was not modified",
		}, nil
	}
	document, err := parseAddonDocument(data, missing, marked)
	if err != nil {
		return nil, fmt.Errorf("parse Recyclarr config: %w", err)
	}
	root, err := documentMapping(document)
	if err != nil {
		return nil, fmt.Errorf("parse Recyclarr config: %w", err)
	}
	for _, name := range []string{"sonarr", "radarr"} {
		if !IsServiceEnabled(cfg, name) {
			continue
		}
		apiKey, keyErr := ReadArrAPIKey(cfg, name)
		if keyErr != nil {
			return nil, fmt.Errorf("read %s API key for Recyclarr: %w", name, keyErr)
		}
		if apiKey == "" {
			return nil, fmt.Errorf("%s API key is unavailable for Recyclarr", name)
		}
		serviceURL, urlErr := StableArrServiceURL(cfg, graph, name)
		if urlErr != nil {
			return nil, fmt.Errorf("resolve %s URL for Recyclarr: %w", name, urlErr)
		}
		instances, mapErr := ensureMappingValue(root, name)
		if mapErr != nil {
			return nil, fmt.Errorf("reconcile Recyclarr %s instances: %w", name, mapErr)
		}
		if len(instances.Content) == 0 {
			instance := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			appendMappingValue(instances, "sdbx", instance)
		}
		for index := 1; index < len(instances.Content); index += 2 {
			instance := instances.Content[index]
			if instance.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("Recyclarr %s instance must be a mapping", name)
			}
			setScalar(instance, "base_url", serviceURL, "!!str")
			setScalar(instance, "api_key", apiKey, "!!str")
		}
	}
	return writeAddonDocument(
		cfg,
		recyclarrConfigName,
		data,
		document,
		missing,
		dryRun,
	)
}

// ReconcileQbitManageConfig creates a valid, deliberately non-destructive
// qbit-manage configuration. Existing managed policy is preserved, but SDBX
// always pins dry_run and every destructive command off.
func ReconcileQbitManageConfig(
	cfg *config.Config,
	dryRun bool,
) (*AddonConfigResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if !IsServiceEnabled(cfg, "qbit-manage") {
		return nil, nil
	}
	data, err := readManagedAddonConfig(cfg, qbitManageConfigName)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return nil, fmt.Errorf("read qbit-manage config: %w", err)
	}
	marked := bytes.HasPrefix(data, []byte(addonManagedMarker))
	document, parseErr := parseAddonDocument(data, missing, marked)
	if parseErr != nil {
		return nil, fmt.Errorf("parse qbit-manage config: %w", parseErr)
	}
	root, mapErr := documentMapping(document)
	if mapErr != nil {
		return nil, fmt.Errorf("parse qbit-manage config: %w", mapErr)
	}
	if !missing && !marked && !isQbitManageStarter(root) {
		return &AddonConfigResult{
			Action: "skipped",
			Reason: "managed-by marker is absent; operator-owned file was not modified",
		}, nil
	}
	password, err := sdbxsecrets.ReadSecret(
		cfg.SecretsPath,
		"qbittorrent_password.txt",
	)
	if err != nil {
		return nil, fmt.Errorf("read qBittorrent credential for qbit-manage: %w", err)
	}
	qbt, err := ensureMappingValue(root, "qbt")
	if err != nil {
		return nil, err
	}
	setScalar(qbt, "host", QBittorrentDockerURL(cfg), "!!str")
	setScalar(qbt, "user", "admin", "!!str")
	setScalar(qbt, "pass", password, "!!str")

	commands, err := ensureMappingValue(root, "commands")
	if err != nil {
		return nil, err
	}
	for _, name := range []string{
		"recheck", "cat_update", "tag_update", "rem_unregistered",
		"tag_tracker_error", "rem_orphaned", "tag_nohardlinks",
		"share_limits", "cleanup_dirs", "skip_cleanup",
		"skip_qb_version_check",
	} {
		setScalar(commands, name, "false", "!!bool")
	}
	setScalar(commands, "dry_run", "true", "!!bool")

	directory, err := ensureMappingValue(root, "directory")
	if err != nil {
		return nil, err
	}
	setScalar(directory, "root_dir", "/downloads", "!!str")
	setScalar(directory, "remote_dir", "/data/downloads", "!!str")
	// qbit-manage persists these defaults during its first startup. Emit them
	// up front so the application and SDBX do not rewrite the managed file in
	// turns after every restart.
	setScalar(directory, "recycle_bin", "/data/downloads/.RecycleBin", "!!str")
	setScalar(directory, "torrents_dir", "null", "!!null")

	categories, err := ensureMappingValue(root, "cat")
	if err != nil {
		return nil, err
	}
	for _, category := range []struct{ name, path string }{
		{"sonarr", qbtCategorySavePath("sonarr")},
		{"radarr", qbtCategorySavePath("radarr")},
		{"lidarr", qbtCategorySavePath("lidarr")},
		{"other", qbtCategorySavePath("other")},
	} {
		setScalar(categories, category.name, category.path, "!!str")
	}
	if IsServiceEnabled(cfg, "whisparr") {
		setScalar(categories, "whisparr", qbtCategorySavePath("whisparr"), "!!str")
	}

	return writeAddonDocument(
		cfg,
		qbitManageConfigName,
		data,
		document,
		missing,
		dryRun,
	)
}

func readManagedAddonConfig(cfg *config.Config, name string) ([]byte, error) {
	root := cfg.ConfigPath
	if root == "" {
		root = "./configs"
	}
	return securefs.ReadRegularFileAt(root, name, maxManagedConfigSize)
}

func parseAddonDocument(data []byte, missing, marked bool) (*yaml.Node, error) {
	if missing {
		return &yaml.Node{
			Kind:    yaml.DocumentNode,
			Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}},
		}, nil
	}
	if marked {
		data = bytes.TrimPrefix(data, []byte(addonManagedMarker))
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	return &document, nil
}

func isQbitManageStarter(root *yaml.Node) bool {
	if root == nil || root.Kind != yaml.MappingNode {
		return false
	}
	for index := 0; index < len(root.Content); index += 2 {
		switch root.Content[index].Value {
		case "settings", "webhooks":
		default:
			return false
		}
	}
	return mappingValue(root, "qbt") == nil &&
		mappingValue(root, "cat") == nil &&
		mappingValue(root, "tracker") == nil
}

func writeAddonDocument(
	cfg *config.Config,
	name string,
	previous []byte,
	document *yaml.Node,
	missing, dryRun bool,
) (*AddonConfigResult, error) {
	rendered, err := yaml.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", name, err)
	}
	rendered = append([]byte(addonManagedMarker), rendered...)
	defer wipeCredentialBytes(rendered)
	action := "updated"
	if missing {
		action = "created"
	} else if bytes.Equal(previous, rendered) {
		action = "kept"
	}
	if dryRun {
		if action == "kept" {
			return &AddonConfigResult{Action: action}, nil
		}
		return &AddonConfigResult{
			Action: "would_" + action,
			Reason: "dry run; managed config was not written",
		}, nil
	}
	if action == "kept" {
		return &AddonConfigResult{Action: action}, nil
	}
	root := cfg.ConfigPath
	if root == "" {
		root = "./configs"
	}
	if err := securefs.WriteFileAtomicOwnedAt(
		root,
		name,
		rendered,
		0o755,
		0o600,
		cfg.PUID,
		cfg.PGID,
	); err != nil {
		return nil, fmt.Errorf("write %s: %w", name, err)
	}
	return &AddonConfigResult{Action: action}, nil
}

func addonConfigIntegrationResult(
	service string,
	result *AddonConfigResult,
	err error,
) *IntegrationResult {
	if result == nil && err == nil {
		return nil
	}
	integration := &IntegrationResult{Service: service, Success: err == nil}
	if result != nil {
		integration.Message = result.Action
		if strings.TrimSpace(result.Reason) != "" {
			integration.Message += ": " + result.Reason
		}
	}
	if err != nil {
		integration.Message = "managed configuration reconciliation failed"
		integration.Error = err
	}
	return integration
}
