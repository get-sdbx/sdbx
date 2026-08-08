package integrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestRenderUnpackerrEnvironmentUsesFileBackedArrKeys(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ConfigPath = filepath.Join(root, "configs")
	cfg.SecretsPath = filepath.Join(root, "secrets")
	cfg.ActiveServices = map[string]bool{
		"sonarr":    true,
		"whisparr":  true,
		"unpackerr": true,
	}
	cfg.Routing.Strategy = config.RoutingStrategyPath
	for name, key := range map[string]string{
		"sonarr":   "synthetic-sonarr-key",
		"whisparr": "synthetic-whisparr-key",
	} {
		directory := filepath.Join(cfg.ConfigPath, name)
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "<Config><ApiKey>" + key + "</ApiKey></Config>"
		if err := os.WriteFile(
			filepath.Join(directory, "config.xml"),
			[]byte(body),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	graph := &registry.ResolutionGraph{
		Services: map[string]*registry.ResolvedService{
			"sonarr": unpackerrResolvedService(
				"sonarr",
				"UN_SONARR_0_URL",
				"UN_SONARR_0_API_KEY",
				"http://sdbx-sonarr:8989",
			),
			"whisparr": unpackerrResolvedService(
				"whisparr",
				"UN_WHISPARR_0_URL",
				"UN_WHISPARR_0_API_KEY",
				"http://sdbx-whisparr:6969",
			),
		},
	}

	if err := RenderUnpackerrEnvironment(cfg, graph); err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(
		filepath.Join(cfg.ConfigPath, "unpackerr", "sdbx.env"),
	)
	if err != nil {
		t.Fatal(err)
	}
	body := string(env)
	for _, expected := range []string{
		"UN_FOLDER_0_PATH=/downloads",
		"UN_SONARR_0_URL=http://sdbx-sonarr:8989/sonarr",
		"UN_SONARR_0_API_KEY=filepath:/run/secrets/unpackerr_sonarr_api_key",
		"UN_SONARR_0_PATHS_0=/downloads",
		"UN_WHISPARR_0_URL=http://sdbx-whisparr:6969/whisparr",
		"UN_WHISPARR_0_API_KEY=filepath:/run/secrets/unpackerr_whisparr_api_key",
		"UN_WHISPARR_0_PATHS_0=/downloads",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("generated environment missing %q:\n%s", expected, body)
		}
	}
	if strings.Contains(body, "synthetic-sonarr-key") ||
		strings.Contains(body, "synthetic-whisparr-key") {
		t.Fatal("plaintext API key leaked into generated environment")
	}
	for name, want := range map[string]string{
		"unpackerr_sonarr_api_key.txt":   "synthetic-sonarr-key",
		"unpackerr_whisparr_api_key.txt": "synthetic-whisparr-key",
	} {
		data, err := os.ReadFile(filepath.Join(cfg.SecretsPath, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != want {
			t.Fatalf("%s = %q, want %q", name, data, want)
		}
		info, err := os.Stat(filepath.Join(cfg.SecretsPath, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode = %o, want 644", name, info.Mode().Perm())
		}
	}
	for _, inactive := range []string{
		"unpackerr_lidarr_api_key.txt",
		"unpackerr_radarr_api_key.txt",
	} {
		data, err := os.ReadFile(filepath.Join(cfg.SecretsPath, inactive))
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != 0 {
			t.Fatalf("inactive secret %s retained data", inactive)
		}
	}
}

func unpackerrResolvedService(
	name, urlEnvVar, apiKeyEnvVar, internalURL string,
) *registry.ResolvedService {
	definition := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: name},
		Routing: registry.RoutingConfig{
			Enabled: true,
			Path:    "/" + name,
			PathRouting: registry.PathRoutingConfig{
				URLBaseEnvVar: strings.ToUpper(name) + "__SERVER__URLBASE",
			},
		},
		Integrations: registry.Integrations{
			Unpackerr: &registry.UnpackerrIntegration{
				Enabled:      true,
				URLEnvVar:    urlEnvVar,
				APIKeyEnvVar: apiKeyEnvVar,
				InternalURL:  internalURL,
			},
		},
	}
	return &registry.ResolvedService{
		Name:            name,
		FinalDefinition: definition,
		Enabled:         true,
	}
}
