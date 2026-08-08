package management

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestContextGateDoesNotQueueCanceledOperations(t *testing.T) {
	var gate contextGate
	if err := gate.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for attempt := 0; attempt < 128; attempt++ {
		if err := gate.Lock(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Lock attempt %d error = %v, want context cancellation", attempt, err)
		}
	}
	gate.Unlock()
	if err := gate.Lock(context.Background()); err != nil {
		t.Fatalf("gate did not recover after canceled waiters: %v", err)
	}
	gate.Unlock()
}

const managementTestVersion = "management-test"

type managementTestResolver struct{}

func (managementTestResolver) Resolve(
	_ context.Context,
	_, _ string,
) (registry.ResolvedImage, error) {
	digest := "sha256:" + strings.Repeat("d", 64)
	return registry.ResolvedImage{
		Digest: digest,
		PlatformDigests: map[string]string{
			"linux/amd64": digest,
			"linux/arm64": digest,
		},
	}, nil
}

func TestProjectOperatorRejectsMissingLock(t *testing.T) {
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "missing-lock.example.test"
	if err := cfg.Save(filepath.Join(projectDir, ".sdbx.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewProjectOperator(
		projectDir,
		managementTestVersion,
		nil,
		managementTestResolver{},
	); err == nil || !strings.Contains(err.Error(), "no .sdbx.lock") {
		t.Fatalf("missing lock error = %v", err)
	}
}

func TestProjectOperatorMutationRejectsTamperedGeneratedState(t *testing.T) {
	projectDir, operator := newManagementTestOperator(t)
	if err := os.WriteFile(
		filepath.Join(projectDir, "compose.yaml"),
		[]byte("tampered\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	_, err := operator.SetAddon(context.Background(), AddonRequest{
		Name:    "sonarr",
		Action:  "enable",
		Confirm: "enable",
	})
	if !errors.Is(err, ErrProjectUnverified) {
		t.Fatalf("tampered mutation error = %v, want ErrProjectUnverified", err)
	}
	reloaded, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.IsAddonEnabled("sonarr") {
		t.Fatal("tampered project was mutated")
	}
}

func TestProjectOperatorMutationRejectsStaleLock(t *testing.T) {
	projectDir, operator := newManagementTestOperator(t)
	cfg, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Domain = "stale-lock.example.test"
	if err := cfg.Save(filepath.Join(projectDir, ".sdbx.yaml")); err != nil {
		t.Fatal(err)
	}
	_, err = operator.SetAddon(context.Background(), AddonRequest{
		Name:    "sonarr",
		Action:  "enable",
		Confirm: "enable",
	})
	if !errors.Is(err, ErrProjectUnverified) {
		t.Fatalf("stale lock mutation error = %v, want ErrProjectUnverified", err)
	}
}

func TestProjectOperatorRestrictsLogsToActiveLockedGraph(t *testing.T) {
	_, operator := newManagementTestOperator(t)
	_, err := operator.Logs(context.Background(), LogsRequest{
		Service: "sonarr",
		Tail:    200,
	})
	if err == nil || !strings.Contains(err.Error(), "active locked graph") {
		t.Fatalf("inactive log error = %v", err)
	}
}

func TestProjectOperatorRequiresExactStackConfirmation(t *testing.T) {
	_, operator := newManagementTestOperator(t)
	for _, request := range []StackRequest{
		{Action: "restart"},
		{Action: "down", Confirm: "restart"},
		{Action: "shell", Confirm: "shell"},
	} {
		err := operator.Stack(context.Background(), request)
		if err == nil {
			t.Fatalf("unsafe stack request %#v was accepted", request)
		}
	}
}

func TestProjectOperatorRejectsManagedRootChangesThroughBroker(t *testing.T) {
	projectDir, operator := newManagementTestOperator(t)
	before, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{
		"config_path",
		"data_path",
		"downloads_path",
		"media_path",
		"secrets_path",
	} {
		_, err := operator.Preview(context.Background(), ImpactRequest{
			Operation: "setting.update",
			Target:    key,
		})
		if err == nil || !strings.Contains(err.Error(), "read-only through the broker") {
			t.Fatalf("Preview(%s) error = %v", key, err)
		}
		_, err = operator.SetSetting(context.Background(), SettingRequest{
			Key:     key,
			Value:   filepath.Join(t.TempDir(), key),
			Confirm: "save",
		})
		if err == nil || !strings.Contains(err.Error(), "read-only through the broker") {
			t.Fatalf("SetSetting(%s) error = %v", key, err)
		}
	}

	after, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigPath != after.ConfigPath ||
		before.DataPath != after.DataPath ||
		before.DownloadsPath != after.DownloadsPath ||
		before.MediaPath != after.MediaPath ||
		before.SecretsPath != after.SecretsPath {
		t.Fatal("broker rejection changed a managed-root path")
	}
}

func TestProjectOperatorSecurityReportComesFromVerifiedState(t *testing.T) {
	_, operator := newManagementTestOperator(t)
	report, err := operator.Security(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !report.ProjectVerified || !report.GeneratedFilesVerified {
		t.Fatalf("verification flags = %#v", report)
	}
	if report.LockedServices == 0 ||
		report.ImmutableImages != report.LockedServices ||
		report.LockSchema != 2 {
		t.Fatalf("lock evidence = %#v", report)
	}
	if report.RouteAuth["admin-only"] == 0 {
		t.Fatalf("route auth evidence = %#v", report.RouteAuth)
	}
}

func TestProjectOperatorSecurityReportsEffectiveVPNNamespace(t *testing.T) {
	_, operator := newManagementTestOperatorWithConfig(
		t,
		func(cfg *config.Config) {
			cfg.VPNEnabled = true
			cfg.VPNProvider = "custom"
		},
	)
	report, err := operator.Security(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !report.VPNEnabled || !report.DownloadVPNEnforced {
		t.Fatalf("VPN security evidence = %#v", report)
	}
}

func TestRootBrokerMutationPreservesProjectOwner(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires a Linux root test environment")
	}
	projectDir, operator := newManagementTestOperator(t)
	const (
		testUID = 12345
		testGID = 12346
	)
	if err := filepath.Walk(projectDir, func(
		path string,
		_ os.FileInfo,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		return os.Chown(path, testUID, testGID)
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := operator.SetAddon(context.Background(), AddonRequest{
		Name:    "sonarr",
		Action:  "enable",
		Confirm: "enable",
	}); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{
		".sdbx.yaml",
		".sdbx.lock",
		".env",
		"compose.yaml",
		"configs",
		"configs/sonarr",
		"configs/traefik/traefik.yml",
	} {
		assertPathOwnership(
			t,
			filepath.Join(projectDir, relative),
			testUID,
			testGID,
		)
	}

	// Files consumed directly by PUID:PGID containers intentionally remain
	// service-owned, while their managed parent stays project-owner-accessible.
	assertPathOwnership(
		t,
		filepath.Join(projectDir, "configs", "sonarr", "config.xml"),
		operatorConfigPUID(t, projectDir),
		operatorConfigPGID(t, projectDir),
	)
}

func newManagementTestOperator(t *testing.T) (string, *ProjectOperator) {
	return newManagementTestOperatorWithConfig(t, nil)
}

func newManagementTestOperatorWithConfig(
	t *testing.T,
	configure func(*config.Config),
) (string, *ProjectOperator) {
	t.Helper()
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "management.example.test"
	cfg.ProjectDir = projectDir
	if configure != nil {
		configure(cfg)
	}
	reg, err := registry.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	lock, _, err := reg.GenerateLockFileWithOptions(
		context.Background(),
		cfg,
		registry.LockOptions{
			CLIVersion:     managementTestVersion,
			TargetPlatform: "linux/" + runtime.GOARCH,
			ImageResolver:  managementTestResolver{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(projectDir, ".sdbx.lock")
	if err := registry.NewLoader().SaveLockFile(lockPath, lock); err != nil {
		t.Fatal(err)
	}
	if err := generator.NewGeneratorWithLock(
		cfg,
		projectDir,
		reg,
		lock,
		managementTestVersion,
	).Generate(); err != nil {
		t.Fatal(err)
	}
	if err := registry.NewLoader().SaveLockFile(lockPath, lock); err != nil {
		t.Fatal(err)
	}
	operator, err := NewProjectOperator(
		projectDir,
		managementTestVersion,
		reg,
		managementTestResolver{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return projectDir, operator
}

func operatorConfigPUID(t *testing.T, projectDir string) int {
	t.Helper()
	cfg, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.PUID
}

func operatorConfigPGID(t *testing.T, projectDir string) int {
	t.Helper()
	cfg, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.PGID
}

func assertPathOwnership(t *testing.T, path string, uid, gid int) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s has no syscall.Stat_t", path)
	}
	if int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Fatalf(
			"%s ownership = %d:%d, want %d:%d",
			path,
			stat.Uid,
			stat.Gid,
			uid,
			gid,
		)
	}
}
