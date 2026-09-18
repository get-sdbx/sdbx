package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/spf13/cobra"
)

type fakeUpdateCompose struct {
	calls      []string
	timeouts   map[string]time.Duration
	failHealth string
	downErr    error
	pullErr    error
	upErr      error
}

type changedUpdateImageResolver struct{}

func (changedUpdateImageResolver) Resolve(
	_ context.Context,
	repository, tag string,
) (registry.ResolvedImage, error) {
	sum := sha256.Sum256([]byte("update-preview:" + repository + ":" + tag))
	digest := fmt.Sprintf("sha256:%x", sum[:])
	return registry.ResolvedImage{
		Digest: digest,
		PlatformDigests: map[string]string{
			"linux/amd64": digest,
			"linux/arm64": digest,
		},
	}, nil
}

type recordingUpdateImageResolver struct {
	calls []string
}

func (r *recordingUpdateImageResolver) Resolve(
	_ context.Context,
	repository, tag string,
) (registry.ResolvedImage, error) {
	r.calls = append(r.calls, updateImageReference(repository, tag))
	return changedUpdateImageResolver{}.Resolve(context.Background(), repository, tag)
}

func TestUpdateImageResolverRefreshesOnlySelectedService(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())
	lock, err := registry.NewLoader().LoadLockFile(filepath.Join(projectDir, ".sdbx.lock"))
	if err != nil {
		t.Fatal(err)
	}
	target := "traefik"
	targetService, ok := lock.Services[target]
	if !ok {
		t.Fatalf("test lock does not contain %s", target)
	}
	refresh := &recordingUpdateImageResolver{}
	resolver, err := updateImageResolver(lock, []string{target}, refresh)
	if err != nil {
		t.Fatal(err)
	}
	for name, service := range lock.Services {
		resolved, resolveErr := resolver.Resolve(
			context.Background(),
			service.Image.Repository,
			service.Image.Tag,
		)
		if resolveErr != nil {
			t.Fatalf("resolve %s: %v", name, resolveErr)
		}
		if name == target {
			if resolved.Digest == service.Image.Digest {
				t.Fatalf("selected service %s retained its old digest", name)
			}
			continue
		}
		if resolved.Digest != service.Image.Digest {
			t.Fatalf("unselected service %s changed digest", name)
		}
	}
	wantReference := updateImageReference(
		targetService.Image.Repository,
		targetService.Image.Tag,
	)
	if len(refresh.calls) != 1 || refresh.calls[0] != wantReference {
		t.Fatalf("upstream resolver calls = %#v, want only %q", refresh.calls, wantReference)
	}
}

func TestUpdateImageResolverRejectsInactiveService(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())
	lock, err := registry.NewLoader().LoadLockFile(filepath.Join(projectDir, ".sdbx.lock"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = updateImageResolver(
		lock,
		[]string{"not-active"},
		&recordingUpdateImageResolver{},
	)
	if err == nil || !strings.Contains(err.Error(), "not active in the verified lock") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunUpdateRejectsExplicitEmptyServiceFlag(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(fmt.Sprint(apply), func(t *testing.T) {
			setupAddonCommandProject(t, config.DefaultConfig())
			refresh := &recordingUpdateImageResolver{}
			oldRefresh, oldCompose := imageRefreshResolverFactory, updateComposeFactory
			oldServices, oldApply, oldConfirm := updateServices, updateApply, updateConfirm
			t.Cleanup(func() {
				imageRefreshResolverFactory, updateComposeFactory = oldRefresh, oldCompose
				updateServices, updateApply, updateConfirm = oldServices, oldApply, oldConfirm
			})
			imageRefreshResolverFactory = func() registry.ImageDigestResolver { return refresh }
			updateComposeFactory = func(string) updateCompose {
				t.Fatal("empty service selection reached a runtime mutation")
				return nil
			}
			command := &cobra.Command{Use: "update", RunE: runUpdate, SilenceErrors: true, SilenceUsage: true}
			command.Flags().StringSliceVar(&updateServices, "service", nil, "")
			command.Flags().BoolVar(&updateApply, "apply", false, "")
			command.Flags().StringVar(&updateConfirm, "confirm", "", "")
			args := []string{"--service="}
			if apply {
				args = append(args, "--apply", "--confirm=apply-upstream-images")
			}
			command.SetArgs(args)
			if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "non-empty service") {
				t.Fatalf("empty explicit scope was not rejected: %v", err)
			}
			if len(refresh.calls) != 0 {
				t.Fatalf("empty explicit scope refreshed images: %v", refresh.calls)
			}
		})
	}
}

func TestUpdateImageResolverRejectsUnselectedSharedImage(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())
	lock, err := registry.NewLoader().LoadLockFile(filepath.Join(projectDir, ".sdbx.lock"))
	if err != nil {
		t.Fatal(err)
	}
	lock.Services["shared-image-service"] = lock.Services["traefik"]
	lock.InstallOrder = append(lock.InstallOrder, "shared-image-service")
	if err := registry.ValidateLockFile(lock, true); err != nil {
		t.Fatal(err)
	}
	refresh := &recordingUpdateImageResolver{}
	if _, err := updateImageResolver(lock, []string{"traefik"}, refresh); err == nil ||
		!strings.Contains(err.Error(), "shared-image-service") {
		t.Fatalf("unselected service sharing the image was not rejected: %v", err)
	}
	if len(refresh.calls) != 0 {
		t.Fatalf("ambiguous scope reached upstream: %v", refresh.calls)
	}
	resolver, err := updateImageResolver(lock, []string{"traefik", "shared-image-service"}, refresh)
	if err != nil {
		t.Fatal(err)
	}
	image := lock.Services["traefik"].Image
	if _, err := resolver.Resolve(context.Background(), image.Repository, image.Tag); err != nil {
		t.Fatal(err)
	}
	if len(refresh.calls) != 1 {
		t.Fatalf("explicit shared-image scope did not refresh: %v", refresh.calls)
	}
}

func TestRunUpdatePreviewScopesUpstreamResolution(t *testing.T) {
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())
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
	beforeEntries := commandTestEntryNames(t, projectDir)

	refresh := &recordingUpdateImageResolver{}
	originalResolverFactory := imageRefreshResolverFactory
	oldServices := updateServices
	oldApply := updateApply
	oldConfirm := updateConfirm
	oldJSON := jsonOut
	imageRefreshResolverFactory = func() registry.ImageDigestResolver { return refresh }
	updateServices = []string{"traefik"}
	updateApply = false
	updateConfirm = ""
	jsonOut = false
	t.Cleanup(func() {
		imageRefreshResolverFactory = originalResolverFactory
		updateServices = oldServices
		updateApply = oldApply
		updateConfirm = oldConfirm
		jsonOut = oldJSON
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	output := captureAddonOutput(t, func() error {
		return runUpdate(command, nil)
	})
	if !strings.Contains(output, "Update Preview") {
		t.Fatalf("scoped update did not produce a preview:\n%s", output)
	}
	if !strings.Contains(
		output,
		"sdbx update --service traefik --apply --confirm apply-upstream-images",
	) {
		t.Fatalf("scoped update preview lost its service selection:\n%s", output)
	}
	if len(refresh.calls) != 1 {
		t.Fatalf("upstream resolver calls = %#v, want one selected image", refresh.calls)
	}
	assertUpdateCommandFilesUnchanged(
		t,
		projectDir,
		configPath,
		lockPath,
		beforeEntries,
		beforeConfig,
		beforeLock,
	)
}

func TestRunUpdatePreviewIsCompleteAndNonMutating(t *testing.T) {
	projectDir := setupChangedUpdateCommandProject(t)
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
	beforeEntries := commandTestEntryNames(t, projectDir)

	originalComposeFactory := updateComposeFactory
	composeCreated := false
	updateComposeFactory = func(string) updateCompose {
		composeCreated = true
		return &fakeUpdateCompose{}
	}
	oldApply := updateApply
	oldConfirm := updateConfirm
	oldJSON := jsonOut
	updateApply = false
	updateConfirm = ""
	jsonOut = false
	t.Cleanup(func() {
		updateComposeFactory = originalComposeFactory
		updateApply = oldApply
		updateConfirm = oldConfirm
		jsonOut = oldJSON
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	output := captureAddonOutput(t, func() error {
		return runUpdate(command, nil)
	})
	for _, expected := range []string{
		"Update Preview",
		"no project files or containers changed",
		"not passed the SDBX release catalog security review",
		"--apply --confirm apply-upstream-images",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("update preview missing %q:\n%s", expected, output)
		}
	}
	if composeCreated {
		t.Fatal("preview constructed a Docker Compose operation")
	}
	assertUpdateCommandFilesUnchanged(
		t,
		projectDir,
		configPath,
		lockPath,
		beforeEntries,
		beforeConfig,
		beforeLock,
	)

	jsonOut = true
	jsonOutput := captureAddonOutput(t, func() error {
		return runUpdate(command, nil)
	})
	var result updateResult
	if err := json.Unmarshal([]byte(jsonOutput), &result); err != nil {
		t.Fatalf("decode update JSON: %v\n%s", err, jsonOutput)
	}
	if !result.Changed || result.Applied || result.RolledBack ||
		len(result.Differences) == 0 || len(result.ServiceOrder) == 0 {
		t.Fatalf("unexpected update preview JSON: %#v", result)
	}
	if composeCreated {
		t.Fatal("JSON preview constructed a Docker Compose operation")
	}
	assertUpdateCommandFilesUnchanged(
		t,
		projectDir,
		configPath,
		lockPath,
		beforeEntries,
		beforeConfig,
		beforeLock,
	)
}

func TestRunUpdateApplyOrchestratesExactLockedCandidate(t *testing.T) {
	projectDir := setupChangedUpdateCommandProject(t)
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
	beforeEntries := commandTestEntryNames(t, projectDir)

	compose := &fakeUpdateCompose{}
	originalComposeFactory := updateComposeFactory
	updateComposeFactory = func(gotProjectDir string) updateCompose {
		gotInfo, gotErr := os.Stat(gotProjectDir)
		wantInfo, wantErr := os.Stat(projectDir)
		if gotErr != nil || wantErr != nil || !os.SameFile(gotInfo, wantInfo) {
			t.Fatalf("Compose project = %q, want %q", gotProjectDir, projectDir)
		}
		return compose
	}
	originalWriter := updateRuntimeWriter
	var writtenLocks []*registry.LockFile
	updateRuntimeWriter = func(
		_ *projectContext,
		lock *registry.LockFile,
	) error {
		writtenLocks = append(writtenLocks, lock)
		return nil
	}
	oldApply := updateApply
	oldConfirm := updateConfirm
	oldJSON := jsonOut
	updateApply = true
	updateConfirm = "apply-upstream-images"
	jsonOut = false
	t.Cleanup(func() {
		updateComposeFactory = originalComposeFactory
		updateRuntimeWriter = originalWriter
		updateApply = oldApply
		updateConfirm = oldConfirm
		jsonOut = oldJSON
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	output := captureAddonOutput(t, func() error {
		return runUpdate(command, nil)
	})
	if !strings.Contains(output, "Updated locked stack is healthy") {
		t.Fatalf("successful update output:\n%s", output)
	}
	if len(writtenLocks) != 1 {
		t.Fatalf("runtime writes = %d, want one candidate write", len(writtenLocks))
	}
	candidate := writtenLocks[0]
	if len(candidate.InstallOrder) == 0 {
		t.Fatal("candidate lock has no install order")
	}
	expectedCalls := []string{"pull", "up"}
	for _, service := range candidate.InstallOrder {
		expectedCalls = append(expectedCalls, "health:"+service)
	}
	if strings.Join(compose.calls, "\x00") != strings.Join(expectedCalls, "\x00") {
		t.Fatalf("Compose calls = %#v, want %#v", compose.calls, expectedCalls)
	}
	assertUpdateCommandFilesUnchanged(
		t,
		projectDir,
		configPath,
		lockPath,
		beforeEntries,
		beforeConfig,
		beforeLock,
	)
}

func setupChangedUpdateCommandProject(t *testing.T) string {
	t.Helper()
	projectDir := setupAddonCommandProject(t, config.DefaultConfig())
	originalResolverFactory := imageRefreshResolverFactory
	imageRefreshResolverFactory = func() registry.ImageDigestResolver {
		return changedUpdateImageResolver{}
	}
	t.Cleanup(func() {
		imageRefreshResolverFactory = originalResolverFactory
	})
	return projectDir
}

func assertUpdateCommandFilesUnchanged(
	t *testing.T,
	projectDir, configPath, lockPath string,
	beforeEntries []string,
	beforeConfig, beforeLock []byte,
) {
	t.Helper()
	afterConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	afterLock, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterConfig) != string(beforeConfig) {
		t.Fatal("update preview modified .sdbx.yaml")
	}
	if string(afterLock) != string(beforeLock) {
		t.Fatal("update preview modified .sdbx.lock")
	}
	afterEntries := commandTestEntryNames(t, projectDir)
	if strings.Join(afterEntries, "\x00") != strings.Join(beforeEntries, "\x00") {
		t.Fatalf(
			"project entries changed from %#v to %#v",
			beforeEntries,
			afterEntries,
		)
	}
}

func commandTestEntryNames(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func (f *fakeUpdateCompose) Pull(context.Context) error {
	f.calls = append(f.calls, "pull")
	return f.pullErr
}

func (f *fakeUpdateCompose) Up(context.Context) error {
	f.calls = append(f.calls, "up")
	return f.upErr
}

func (f *fakeUpdateCompose) Down(context.Context) error {
	f.calls = append(f.calls, "down")
	return f.downErr
}

func (f *fakeUpdateCompose) WaitHealthy(
	_ context.Context,
	service string,
	timeout time.Duration,
) error {
	f.calls = append(f.calls, "health:"+service)
	if f.timeouts == nil {
		f.timeouts = make(map[string]time.Duration)
	}
	f.timeouts[service] = timeout
	if service == f.failHealth {
		return errors.New("unhealthy")
	}
	return nil
}

func TestWaitForUpdateHealthUsesActiveLockOrderAndStopsOnFailure(t *testing.T) {
	compose := &fakeUpdateCompose{failHealth: "qbittorrent"}
	err := waitForUpdateHealth(
		context.Background(),
		compose,
		[]string{"gluetun", "qbittorrent", "sonarr"},
		map[string]time.Duration{
			"gluetun":     4*time.Minute + 30*time.Second,
			"qbittorrent": 2 * time.Minute,
			"sonarr":      90 * time.Second,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "qbittorrent") {
		t.Fatalf("error = %v, want qBittorrent health failure", err)
	}
	want := []string{"health:gluetun", "health:qbittorrent"}
	if strings.Join(compose.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls = %#v, want %#v", compose.calls, want)
	}
	if compose.timeouts["gluetun"] != 4*time.Minute+30*time.Second {
		t.Fatalf("Gluetun timeout = %s", compose.timeouts["gluetun"])
	}
}

func TestWaitForUpdateHealthRejectsMissingOrder(t *testing.T) {
	if err := waitForUpdateHealth(
		context.Background(),
		&fakeUpdateCompose{},
		nil,
		nil,
	); err == nil {
		t.Fatal("empty active service order was accepted")
	}
}

func TestUpdateHealthTimeoutHonorsGluetunColdStartGrace(t *testing.T) {
	timeout, err := updateHealthTimeout(&registry.HealthCheck{
		Interval:    "30s",
		Timeout:     "10s",
		Retries:     3,
		StartPeriod: "120s",
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = 4*time.Minute + 30*time.Second
	if timeout != want {
		t.Fatalf("timeout = %s, want %s", timeout, want)
	}
	if timeout <= 120*time.Second {
		t.Fatalf("timeout %s does not preserve the cold-start grace", timeout)
	}
}

func TestResolvedUpdateHealthTimeoutUsesEmbeddedGluetunPolicy(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = true
	cfg.VPNProvider = "nordvpn"
	cfg.VPNCountry = "France"
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	timeouts, err := resolveUpdateHealthTimeouts(
		context.Background(),
		&projectContext{Config: cfg, Registry: reg},
	)
	if err != nil {
		t.Fatal(err)
	}
	const want = 4*time.Minute + 30*time.Second
	if timeouts["gluetun"] != want {
		t.Fatalf("embedded Gluetun timeout = %s, want %s", timeouts["gluetun"], want)
	}
}

func TestUpdateHealthTimeoutIsBoundedAndRejectsInvalidPolicy(t *testing.T) {
	if timeout, err := updateHealthTimeout(nil); err != nil ||
		timeout != updateMinimumHealthTimeout {
		t.Fatalf("nil health timeout = %s, %v", timeout, err)
	}
	for _, health := range []*registry.HealthCheck{
		{StartPeriod: "invalid"},
		{StartPeriod: "20m"},
		{Retries: -1},
		{Retries: 21},
	} {
		if _, err := updateHealthTimeout(health); err == nil {
			t.Fatalf("invalid health policy accepted: %#v", health)
		}
	}
}

func TestRollbackUpdateRestoresRuntimeBeforeReconverging(t *testing.T) {
	originalWriter := updateRuntimeWriter
	t.Cleanup(func() {
		updateRuntimeWriter = originalWriter
	})

	previous := &registry.LockFile{
		InstallOrder: []string{"traefik", "authelia"},
	}
	var restored *registry.LockFile
	updateRuntimeWriter = func(_ *projectContext, lock *registry.LockFile) error {
		restored = lock
		return nil
	}
	compose := &fakeUpdateCompose{}
	if err := rollbackUpdate(
		context.Background(),
		&projectContext{},
		compose,
		previous,
		nil,
		false,
	); err != nil {
		t.Fatal(err)
	}
	if restored != previous {
		t.Fatal("rollback did not restore the previous lock")
	}
	want := []string{"pull", "up", "health:traefik", "health:authelia"}
	if strings.Join(compose.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls = %#v, want %#v", compose.calls, want)
	}
}

func TestRollbackUpdateResetsFailedContainersBeforeReconverging(t *testing.T) {
	originalWriter := updateRuntimeWriter
	t.Cleanup(func() {
		updateRuntimeWriter = originalWriter
	})
	updateRuntimeWriter = func(_ *projectContext, _ *registry.LockFile) error {
		return nil
	}
	compose := &fakeUpdateCompose{}
	err := rollbackUpdate(
		context.Background(),
		&projectContext{},
		compose,
		&registry.LockFile{InstallOrder: []string{"gluetun", "qbittorrent"}},
		nil,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"down",
		"pull",
		"up",
		"health:gluetun",
		"health:qbittorrent",
	}
	if strings.Join(compose.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls = %#v, want %#v", compose.calls, want)
	}
}

func TestRollbackUpdateStopsWhenFailedContainersCannotBeReset(t *testing.T) {
	originalWriter := updateRuntimeWriter
	t.Cleanup(func() {
		updateRuntimeWriter = originalWriter
	})
	updateRuntimeWriter = func(_ *projectContext, _ *registry.LockFile) error {
		return nil
	}
	compose := &fakeUpdateCompose{downErr: errors.New("compose down failed")}
	err := rollbackUpdate(
		context.Background(),
		&projectContext{},
		compose,
		&registry.LockFile{InstallOrder: []string{"gluetun"}},
		nil,
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "stop failed updated stack") {
		t.Fatalf("error = %v, want reset failure", err)
	}
	if strings.Join(compose.calls, ",") != "down" {
		t.Fatalf("calls = %#v, want down only", compose.calls)
	}
}

func TestRollbackUpdateReportsReconvergenceFailure(t *testing.T) {
	originalWriter := updateRuntimeWriter
	t.Cleanup(func() {
		updateRuntimeWriter = originalWriter
	})
	updateRuntimeWriter = func(_ *projectContext, _ *registry.LockFile) error {
		return nil
	}
	compose := &fakeUpdateCompose{upErr: errors.New("compose failed")}
	err := rollbackUpdate(
		context.Background(),
		&projectContext{},
		compose,
		&registry.LockFile{InstallOrder: []string{"traefik"}},
		nil,
		false,
	)
	if err == nil || !strings.Contains(err.Error(), "reconverge previous stack") {
		t.Fatalf("error = %v, want rollback reconvergence failure", err)
	}
}

func TestUpdateFailureDistinguishesSuccessfulAndFailedRollback(t *testing.T) {
	cause := errors.New("new stack failed")
	if message := updateFailure("deploy", cause, nil).Error(); !strings.Contains(
		message,
		"previous locked stack restored",
	) {
		t.Fatalf("successful rollback message = %q", message)
	}
	rollbackErr := errors.New("old stack failed")
	if message := updateFailure("deploy", cause, rollbackErr).Error(); !strings.Contains(
		message,
		"automatic rollback also failed",
	) {
		t.Fatalf("failed rollback message = %q", message)
	}
}

func TestLockContainsLocalSource(t *testing.T) {
	lock := &registry.LockFile{
		Sources: map[string]registry.LockedSource{
			"custom": {Type: "local"},
		},
	}
	if !lockContainsLocalSource(lock) {
		t.Fatal("local source was not preserved for an authorized lock refresh")
	}
	if lockContainsLocalSource(nil) {
		t.Fatal("nil lock reported a local source")
	}
}

func TestPrintUpdateResultDefaultsToNonMutatingPreview(t *testing.T) {
	result := updateResult{
		Changed: true,
		Differences: []registry.LockFileDiff{{
			Type:        "changed",
			Description: "authelia image digest changed",
		}},
	}
	output := captureAddonOutput(t, func() error {
		return printUpdateResult(result, nil)
	})
	for _, expected := range []string{
		"Update Preview",
		"no project files or containers changed",
		"not passed the SDBX release catalog security review",
		"--apply --confirm apply-upstream-images",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("preview output missing %q:\n%s", expected, output)
		}
	}
}

func TestUpdateApplyRequiresExactSupplyChainConfirmation(t *testing.T) {
	for _, confirmation := range []string{"", "yes", "apply", "Apply-Upstream-Images"} {
		err := validateUpdateApplyConfirmation(confirmation)
		if err == nil || !strings.Contains(err.Error(), "--confirm apply-upstream-images") {
			t.Fatalf("confirmation %q error = %v", confirmation, err)
		}
	}
	if err := validateUpdateApplyConfirmation("apply-upstream-images"); err != nil {
		t.Fatalf("exact update confirmation rejected: %v", err)
	}
}
