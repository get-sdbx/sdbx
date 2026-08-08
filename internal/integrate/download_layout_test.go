package integrate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
)

func TestPrepareDownloadLayoutCreatesDirectoriesWithoutMovingExistingFiles(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "legacy-file")
	if err := os.WriteFile(legacy, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.DownloadsPath = root
	cfg.PUID = os.Getuid()
	cfg.PGID = os.Getgid()
	if err := PrepareDownloadLayout(cfg, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range ManagedDownloadDirectories {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil || !info.IsDir() {
			t.Fatalf("managed directory %s: info=%v err=%v", name, info, err)
		}
	}
	if body, err := os.ReadFile(legacy); err != nil || string(body) != "keep" {
		t.Fatalf("legacy file changed: %q err=%v", body, err)
	}
}

func TestPrepareDownloadLayoutRejectsManagedSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "movies")); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.DownloadsPath = root
	if err := PrepareDownloadLayout(cfg, false); err == nil {
		t.Fatal("managed symlink was accepted")
	}
}
