package integrate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
	"github.com/get-sdbx/sdbx/internal/securefs"
	"gopkg.in/yaml.v3"
)

const (
	decluttarrConfigName    = "decluttarr/config.yaml"
	decluttarrManagedMarker = "# managed-by: sdbx\n"
	decluttarrQBTComment    = "qBittorrent shares Gluetun's network namespace and is reached through\n" +
		"the Gluetun container endpoint. SDBX-managed authentication is required."
)

// DecluttarrConfigResult reports the non-secret outcome of a managed config
// reconciliation.
type DecluttarrConfigResult struct {
	Action string
	Reason string
}

// ReconcileDecluttarrConfig keeps the SDBX-managed Decluttarr v2 config wired
// to current internal endpoints and credentials. Existing cleanup jobs and
// operator tuning are preserved. Removing the first-line managed marker is an
// explicit opt-out: SDBX then leaves the file byte-for-byte untouched.
func ReconcileDecluttarrConfig(
	cfg *config.Config,
	graph *registry.ResolutionGraph,
	dryRun bool,
) (*DecluttarrConfigResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if !IsServiceEnabled(cfg, "decluttarr") {
		return nil, nil
	}
	configRoot := cfg.ConfigPath
	if configRoot == "" {
		configRoot = "./configs"
	}
	data, err := securefs.ReadRegularFileAt(
		configRoot,
		decluttarrConfigName,
		maxManagedConfigSize,
	)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return nil, fmt.Errorf("read Decluttarr managed config: %w", err)
	}
	if !missing && !bytes.HasPrefix(data, []byte(decluttarrManagedMarker)) {
		return &DecluttarrConfigResult{
			Action: "skipped",
			Reason: "managed-by marker is absent; operator-owned file was not modified",
		}, nil
	}

	document, err := parseDecluttarrDocument(data, missing)
	if err != nil {
		return nil, err
	}
	root, err := documentMapping(document)
	if err != nil {
		return nil, err
	}
	general, err := ensureMappingValue(root, "general")
	if err != nil {
		return nil, err
	}
	setScalar(general, "test_run", "true", "!!bool")

	instances, err := ensureMappingValue(root, "instances")
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"sonarr", "radarr", "lidarr", "whisparr"} {
		if !IsServiceEnabled(cfg, name) {
			continue
		}
		apiKey, err := ReadArrAPIKey(cfg, name)
		if err != nil {
			return nil, fmt.Errorf("read %s API key for Decluttarr: %w", name, err)
		}
		if apiKey == "" {
			return nil, fmt.Errorf("%s API key is unavailable for Decluttarr", name)
		}
		serviceURL, urlErr := StableArrServiceURL(cfg, graph, name)
		if urlErr != nil {
			return nil, fmt.Errorf("resolve %s URL for Decluttarr: %w", name, urlErr)
		}
		instance, err := ensureFirstSequenceMapping(instances, name)
		if err != nil {
			return nil, err
		}
		setScalar(instance, "base_url", serviceURL, "!!str")
		setScalar(instance, "api_key", apiKey, "!!str")
	}

	password, err := sdbxsecrets.ReadSecret(
		cfg.SecretsPath,
		"qbittorrent_password.txt",
	)
	if err != nil {
		return nil, fmt.Errorf("read qBittorrent credential for Decluttarr: %w", err)
	}
	downloadClients, err := ensureMappingValue(root, "download_clients")
	if err != nil {
		return nil, err
	}
	qbittorrent, err := ensureFirstSequenceMapping(
		downloadClients,
		"qbittorrent",
	)
	if err != nil {
		return nil, err
	}
	setScalar(qbittorrent, "base_url", QBittorrentDockerURL(cfg), "!!str")
	setScalar(qbittorrent, "username", "admin", "!!str")
	setScalar(qbittorrent, "password", password, "!!str")
	reconcileDecluttarrQBTComment(qbittorrent)

	rendered, err := yaml.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("render Decluttarr managed config: %w", err)
	}
	rendered = append([]byte(decluttarrManagedMarker), rendered...)
	defer wipeCredentialBytes(rendered)
	action := "updated"
	if missing {
		action = "created"
	} else if bytes.Equal(data, rendered) {
		action = "kept"
	}
	if dryRun {
		if action == "kept" {
			return &DecluttarrConfigResult{Action: action}, nil
		}
		return &DecluttarrConfigResult{
			Action: "would_" + action,
			Reason: "dry run; managed config was not written",
		}, nil
	}
	if action == "kept" {
		return &DecluttarrConfigResult{Action: action}, nil
	}
	if err := securefs.EnsureDir(configRoot, 0o755); err != nil {
		return nil, fmt.Errorf("prepare Decluttarr config root: %w", err)
	}
	if err := securefs.WriteFileAtomicOwnedAt(
		configRoot,
		decluttarrConfigName,
		rendered,
		0o755,
		0o600,
		cfg.PUID,
		cfg.PGID,
	); err != nil {
		return nil, fmt.Errorf("write Decluttarr managed config: %w", err)
	}
	return &DecluttarrConfigResult{Action: action}, nil
}

func reconcileDecluttarrQBTComment(qbittorrent *yaml.Node) {
	var visit func(*yaml.Node)
	visit = func(node *yaml.Node) {
		if node == nil {
			return
		}
		for _, comment := range []*string{
			&node.HeadComment,
			&node.LineComment,
			&node.FootComment,
		} {
			if strings.Contains(*comment, "whitelisted in qBT") ||
				strings.Contains(*comment, "no credentials needed") {
				*comment = ""
			}
		}
		for _, child := range node.Content {
			visit(child)
		}
	}
	visit(qbittorrent)
	qbittorrent.HeadComment = decluttarrQBTComment
}

func parseDecluttarrDocument(data []byte, missing bool) (*yaml.Node, error) {
	if missing {
		return &yaml.Node{
			Kind: yaml.DocumentNode,
			Content: []*yaml.Node{{
				Kind: yaml.MappingNode,
				Tag:  "!!map",
			}},
		}, nil
	}
	body := bytes.TrimPrefix(data, []byte(decluttarrManagedMarker))
	var document yaml.Node
	if err := yaml.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("parse Decluttarr managed config: %w", err)
	}
	return &document, nil
}

func documentMapping(document *yaml.Node) (*yaml.Node, error) {
	if document == nil ||
		document.Kind != yaml.DocumentNode ||
		len(document.Content) != 1 ||
		document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("Decluttarr managed config must be a YAML mapping")
	}
	return document.Content[0], nil
}

func ensureMappingValue(mapping *yaml.Node, key string) (*yaml.Node, error) {
	value := mappingValue(mapping, key)
	if value == nil {
		value = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		appendMappingValue(mapping, key, value)
		return value, nil
	}
	if value.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("Decluttarr %s must be a YAML mapping", key)
	}
	return value, nil
}

func ensureFirstSequenceMapping(mapping *yaml.Node, key string) (*yaml.Node, error) {
	sequence := mappingValue(mapping, key)
	if sequence == nil {
		sequence = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		appendMappingValue(mapping, key, sequence)
	}
	if sequence.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("Decluttarr %s must be a YAML sequence", key)
	}
	if len(sequence.Content) == 0 {
		sequence.Content = append(sequence.Content, &yaml.Node{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
		})
	}
	if sequence.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("Decluttarr %s first instance must be a mapping", key)
	}
	return sequence.Content[0], nil
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func appendMappingValue(mapping *yaml.Node, key string, value *yaml.Node) {
	mapping.Content = append(
		mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		value,
	)
}

func setScalar(mapping *yaml.Node, key, value, tag string) {
	node := mappingValue(mapping, key)
	if node == nil {
		node = &yaml.Node{}
		appendMappingValue(mapping, key, node)
	}
	node.Kind = yaml.ScalarNode
	node.Tag = tag
	node.Value = value
	node.Content = nil
	node.Alias = nil
}

func decluttarrConfigPath(cfg *config.Config) string {
	root := cfg.ConfigPath
	if root == "" {
		root = "./configs"
	}
	return filepath.Join(root, filepath.FromSlash(decluttarrConfigName))
}
