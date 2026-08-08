package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/integrate"
	"github.com/spf13/cobra"
)

func TestNetworkIntegrationsRequiredUsesEnabledServicePairs(t *testing.T) {
	tests := []struct {
		name     string
		services map[string]*integrate.ServiceConfig
		want     bool
	}{
		{
			name: "prowlarr and sonarr",
			services: integrationServices(
				"prowlarr",
				"sonarr",
			),
			want: true,
		},
		{
			name: "qbittorrent and lidarr",
			services: integrationServices(
				"qbittorrent",
				"lidarr",
			),
			want: true,
		},
		{
			name: "qbittorrent and whisparr",
			services: integrationServices(
				"qbittorrent",
				"whisparr",
			),
			want: true,
		},
		{
			name: "tautulli and plex",
			services: integrationServices(
				"tautulli",
				"plex",
			),
			want: true,
		},
		{
			name: "tautulli without plex",
			services: integrationServices(
				"tautulli",
			),
			want: false,
		},
		{
			name: "arr without coordinator",
			services: integrationServices(
				"sonarr",
			),
			want: false,
		},
		{
			name: "coordinator without arr",
			services: integrationServices(
				"prowlarr",
				"qbittorrent",
			),
			want: false,
		},
		{
			name: "disabled pair",
			services: map[string]*integrate.ServiceConfig{
				"prowlarr": {Name: "prowlarr", Enabled: true},
				"sonarr":   {Name: "sonarr", Enabled: false},
			},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := networkIntegrationsRequired(test.services); got != test.want {
				t.Fatalf("networkIntegrationsRequired() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAddHostInitializationPreviewListsOnlyEnabledInitializers(t *testing.T) {
	initialization := make(map[string]any)
	addHostInitializationPreview(
		initialization,
		&config.Config{
			ActiveServices: map[string]bool{
				"qbittorrent": true,
				"filebrowser": false,
			},
		},
		false,
	)

	qbittorrent, ok := initialization["qbittorrent"].(map[string]any)
	if !ok {
		t.Fatal("qBittorrent preview is missing")
	}
	if qbittorrent["action"] != "would-initialize-if-needed" {
		t.Fatalf("qBittorrent preview = %#v", qbittorrent)
	}
	if _, ok := initialization["filebrowser"]; ok {
		t.Fatal("disabled File Browser appeared in the preview")
	}
}

func TestRunIntegrateHumanDryRunPreviewsFreshProjectWithoutMutation(t *testing.T) {
	projectDir, callerDir, beforeEntries, beforeConfig, beforeLock :=
		setupIntegratePreviewProject(t)
	setIntegrateTestFlags(t, false)
	hostResolutionCalls := recordHostEndpointResolutionCalls(t)

	command := &cobra.Command{}
	command.SetContext(context.Background())
	output := captureAddonOutput(t, func() error {
		return runIntegrate(command, nil)
	})
	for _, expected := range []string{
		"DRY RUN MODE",
		"Local initialization preview:",
		"filebrowser: initialize or repair managed credentials if needed",
		"qbittorrent: initialize or repair managed credentials if needed",
		"Services with API credentials detected:",
		"none",
		"No API integrations are ready",
		"Local initialization preview completed",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("integrate dry-run output missing %q:\n%s", expected, output)
		}
	}
	assertIntegratePreviewUnchanged(
		t,
		projectDir,
		callerDir,
		beforeEntries,
		beforeConfig,
		beforeLock,
	)
	if *hostResolutionCalls != 0 {
		t.Fatalf("host endpoint resolution calls = %d, want zero", *hostResolutionCalls)
	}
}

func TestRunIntegrateJSONDryRunPreviewsFreshProjectWithoutMutation(t *testing.T) {
	projectDir, callerDir, beforeEntries, beforeConfig, beforeLock :=
		setupIntegratePreviewProject(t)
	setIntegrateTestFlags(t, true)
	hostResolutionCalls := recordHostEndpointResolutionCalls(t)

	command := &cobra.Command{}
	command.SetContext(context.Background())
	output := captureAddonOutput(t, func() error {
		return runIntegrate(command, nil)
	})

	var result struct {
		Success        bool                      `json:"success"`
		Total          int                       `json:"total"`
		Successful     int                       `json:"successful"`
		Failed         int                       `json:"failed"`
		Integrations   []map[string]any          `json:"integrations"`
		Initialization map[string]map[string]any `json:"initialization"`
		Network        map[string]any            `json:"network_integrations"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("decode integrate JSON: %v\n%s", err, output)
	}
	if !result.Success || result.Total != 0 || result.Successful != 0 ||
		result.Failed != 0 || len(result.Integrations) != 0 {
		t.Fatalf("unexpected integrate dry-run summary: %#v", result)
	}
	for _, name := range []string{"filebrowser", "qbittorrent"} {
		preview, ok := result.Initialization[name]
		if !ok {
			t.Fatalf("%s initialization preview is missing: %#v", name, result)
		}
		if preview["action"] != "would-initialize-if-needed" ||
			preview["password_set"] != false {
			t.Fatalf("%s initialization preview = %#v", name, preview)
		}
	}
	if result.Network["required"] != false ||
		result.Network["status"] != "not-required" ||
		result.Network["runner"] != "none" {
		t.Fatalf("unexpected network integration report: %#v", result.Network)
	}
	assertIntegratePreviewUnchanged(
		t,
		projectDir,
		callerDir,
		beforeEntries,
		beforeConfig,
		beforeLock,
	)
	if *hostResolutionCalls != 0 {
		t.Fatalf("host endpoint resolution calls = %d, want zero", *hostResolutionCalls)
	}
}

func TestRunIntegrateRestoresWorkingDirectoryOnError(t *testing.T) {
	projectDir, callerDir, beforeEntries, beforeConfig, beforeLock :=
		setupIntegratePreviewProject(t)
	setIntegrateTestFlags(t, true)
	integrateInCluster = true
	hostResolutionCalls := recordHostEndpointResolutionCalls(t)

	command := &cobra.Command{}
	command.SetContext(context.Background())
	err := runIntegrate(command, nil)
	if err == nil ||
		!strings.Contains(err.Error(), "no services with usable integration credentials") {
		t.Fatalf("runIntegrate() error = %v", err)
	}
	assertIntegratePreviewUnchanged(
		t,
		projectDir,
		callerDir,
		beforeEntries,
		beforeConfig,
		beforeLock,
	)
	if *hostResolutionCalls != 0 {
		t.Fatalf("host endpoint resolution calls = %d, want zero", *hostResolutionCalls)
	}
}

func TestNativeArrAuthenticationRequired(t *testing.T) {
	for _, test := range []struct {
		name     string
		services map[string]*integrate.ServiceConfig
		want     bool
	}{
		{
			name:     "sonarr",
			services: integrationServices("sonarr"),
			want:     true,
		},
		{
			name:     "prowlarr",
			services: integrationServices("prowlarr"),
			want:     true,
		},
		{
			name:     "radarr",
			services: integrationServices("radarr"),
			want:     true,
		},
		{
			name:     "lidarr",
			services: integrationServices("lidarr"),
			want:     true,
		},
		{
			name:     "unrelated service",
			services: integrationServices("qbittorrent"),
			want:     false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := nativeArrAuthenticationRequired(test.services); got != test.want {
				t.Fatalf(
					"nativeArrAuthenticationRequired() = %t, want %t",
					got,
					test.want,
				)
			}
		})
	}
}

func TestIntegrateCredentialRotationRequiresExactConfirmation(t *testing.T) {
	setIntegrateTestFlags(t, false)
	integrateDryRun = false
	integrateRotateManagedCredentials = true
	for _, confirmation := range []string{"", "yes", "rotate"} {
		integrateRotateConfirmation = confirmation
		err := runIntegrate(integrateCmd, nil)
		if err == nil || !strings.Contains(err.Error(), "--confirm rotate-managed-credentials") {
			t.Fatalf("confirmation %q error = %v", confirmation, err)
		}
	}
}

func TestSortedIntegrationServiceNamesIsDeterministic(t *testing.T) {
	services := map[string]*integrate.ServiceConfig{
		"sonarr":      {Name: "sonarr", Enabled: true},
		"filebrowser": {Name: "filebrowser", Enabled: true},
		"prowlarr":    {Name: "prowlarr", Enabled: false},
	}
	got := sortedIntegrationServiceNames(services)
	want := []string{"filebrowser", "prowlarr", "sonarr"}
	if len(got) != len(want) {
		t.Fatalf("names = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("names = %#v, want %#v", got, want)
		}
	}
}

func TestBuildNetworkIntegrationReport(t *testing.T) {
	for _, test := range []struct {
		name                         string
		hostControlRequired          bool
		serviceToServiceRequired     bool
		nativeAuthenticationRequired bool
		dryRun                       bool
		inCluster                    bool
		wantStatus                   string
		wantRunner                   string
	}{
		{
			name:       "no network work",
			wantStatus: "not-required",
			wantRunner: "none",
		},
		{
			name:                         "native authentication on host",
			hostControlRequired:          true,
			nativeAuthenticationRequired: true,
			wantStatus:                   "executed",
			wantRunner:                   "linux-host-docker-bridge",
		},
		{
			name:                     "service integration preview",
			hostControlRequired:      true,
			serviceToServiceRequired: true,
			dryRun:                   true,
			wantStatus:               "previewed",
			wantRunner:               "linux-host-docker-bridge",
		},
		{
			name:                         "combined in cluster",
			hostControlRequired:          true,
			serviceToServiceRequired:     true,
			nativeAuthenticationRequired: true,
			inCluster:                    true,
			wantStatus:                   "executed",
			wantRunner:                   "explicit-in-cluster",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := buildNetworkIntegrationReport(
				test.hostControlRequired,
				test.serviceToServiceRequired,
				test.nativeAuthenticationRequired,
				test.dryRun,
				test.inCluster,
			)
			if report["required"] != test.hostControlRequired {
				t.Fatalf(
					"required = %#v, want %t",
					report["required"],
					test.hostControlRequired,
				)
			}
			if report["service_to_service_required"] !=
				test.serviceToServiceRequired {
				t.Fatalf(
					"service_to_service_required = %#v, want %t",
					report["service_to_service_required"],
					test.serviceToServiceRequired,
				)
			}
			if report["native_authentication_required"] !=
				test.nativeAuthenticationRequired {
				t.Fatalf(
					"native_authentication_required = %#v, want %t",
					report["native_authentication_required"],
					test.nativeAuthenticationRequired,
				)
			}
			if report["status"] != test.wantStatus {
				t.Fatalf(
					"status = %#v, want %q",
					report["status"],
					test.wantStatus,
				)
			}
			if report["runner"] != test.wantRunner {
				t.Fatalf(
					"runner = %#v, want %q",
					report["runner"],
					test.wantRunner,
				)
			}
		})
	}
}

func integrationServices(names ...string) map[string]*integrate.ServiceConfig {
	services := make(map[string]*integrate.ServiceConfig, len(names))
	for _, name := range names {
		services[name] = &integrate.ServiceConfig{
			Name:    name,
			Enabled: true,
		}
	}
	return services
}

func setupIntegratePreviewProject(
	t *testing.T,
) (string, string, []string, []byte, []byte) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.EnableAddon("filebrowser")
	projectDir := setupAddonCommandProject(t, cfg)

	callerDir := filepath.Join(projectDir, "caller")
	if err := os.Mkdir(callerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(callerDir); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(projectDir, ".sdbx.yaml")
	lockPath := filepath.Join(projectDir, ".sdbx.lock")
	beforeConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeLock, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	return projectDir, callerDir, commandTestEntryNames(t, projectDir),
		beforeConfig, beforeLock
}

func setIntegrateTestFlags(t *testing.T, json bool) {
	t.Helper()
	oldDryRun := integrateDryRun
	oldVerbose := integrateVerbose
	oldInCluster := integrateInCluster
	oldRotate := integrateRotateManagedCredentials
	oldConfirmation := integrateRotateConfirmation
	oldJSON := jsonOut
	integrateDryRun = true
	integrateVerbose = false
	integrateInCluster = false
	integrateRotateManagedCredentials = false
	integrateRotateConfirmation = ""
	jsonOut = json
	t.Cleanup(func() {
		integrateDryRun = oldDryRun
		integrateVerbose = oldVerbose
		integrateInCluster = oldInCluster
		integrateRotateManagedCredentials = oldRotate
		integrateRotateConfirmation = oldConfirmation
		jsonOut = oldJSON
	})
}

func recordHostEndpointResolutionCalls(t *testing.T) *int {
	t.Helper()
	original := resolveHostIntegrationEndpoints
	calls := 0
	resolveHostIntegrationEndpoints = func(
		context.Context,
		*config.Config,
		map[string]*integrate.ServiceConfig,
		integrate.ContainerAddressResolver,
	) error {
		calls++
		return nil
	}
	t.Cleanup(func() {
		resolveHostIntegrationEndpoints = original
	})
	return &calls
}

func assertIntegratePreviewUnchanged(
	t *testing.T,
	projectDir, callerDir string,
	beforeEntries []string,
	beforeConfig, beforeLock []byte,
) {
	t.Helper()
	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	currentInfo, currentErr := os.Stat(currentDir)
	callerInfo, callerErr := os.Stat(callerDir)
	if currentErr != nil || callerErr != nil ||
		!os.SameFile(currentInfo, callerInfo) {
		t.Fatalf("working directory = %q, want restored to %q", currentDir, callerDir)
	}
	assertUpdateCommandFilesUnchanged(
		t,
		projectDir,
		filepath.Join(projectDir, ".sdbx.yaml"),
		filepath.Join(projectDir, ".sdbx.lock"),
		beforeEntries,
		beforeConfig,
		beforeLock,
	)
}
