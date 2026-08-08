package registry

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCacheRepoPathCannotEscapeBaseDir(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir)

	repoPath := cache.GetRepoPath("../escape")

	rel, err := filepath.Rel(baseDir, repoPath)
	if err != nil {
		t.Fatalf("Rel failed: %v", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("repo path escaped cache base: %s", repoPath)
	}
	if strings.Contains(filepath.Base(repoPath), "..") {
		t.Fatalf("repo path kept traversal tokens: %s", repoPath)
	}
}

func TestCacheRepoPathAvoidsSanitizedNameCollisions(t *testing.T) {
	cache := NewCache(t.TempDir())

	first := cache.GetRepoPath("team/services")
	second := cache.GetRepoPath("team-services")

	if first == second {
		t.Fatalf("different source names mapped to same cache path: %s", first)
	}
}

func TestCachePromoteRepoAtomicallyReplacesActiveCheckout(t *testing.T) {
	cache := NewCache(t.TempDir())
	activePath := cache.GetRepoPath("community")
	if err := os.Mkdir(activePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(activePath, "version"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	stagingPath, err := cache.CreateStagingDir("community")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingPath, "version"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cache.PromoteRepo("community", stagingPath); err != nil {
		t.Fatalf("PromoteRepo failed: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(activePath, "version"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new" {
		t.Fatalf("active cache content = %q, want new", content)
	}
	if _, err := os.Stat(stagingPath); !os.IsNotExist(err) {
		t.Fatalf("staging path still exists after promotion: %v", err)
	}
}

func TestCacheRejectsOversizedStagingAndPreservesActiveCheckout(t *testing.T) {
	cache := NewCache(t.TempDir())
	activePath := cache.GetRepoPath("community")
	if err := os.Mkdir(activePath, 0o700); err != nil {
		t.Fatal(err)
	}
	activeMarker := filepath.Join(activePath, "verified")
	if err := os.WriteFile(activeMarker, []byte("last-good"), 0o600); err != nil {
		t.Fatal(err)
	}

	stagingPath, err := cache.CreateStagingDir("community")
	if err != nil {
		t.Fatal(err)
	}
	oversizedPath := filepath.Join(stagingPath, "oversized")
	if err := os.WriteFile(oversizedPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(oversizedPath, externalSourceCacheLimit+1); err != nil {
		t.Fatal(err)
	}

	err = cache.PromoteRepo("community", stagingPath)
	var resourceErr *sourceResourceError
	if !errors.As(err, &resourceErr) {
		t.Fatalf("PromoteRepo error = %v, want source resource error", err)
	}
	content, readErr := os.ReadFile(activeMarker)
	if readErr != nil {
		t.Fatalf("active checkout was not preserved: %v", readErr)
	}
	if string(content) != "last-good" {
		t.Fatalf("active checkout changed to %q", content)
	}
}

func TestValidateSourceWorkingTreeRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "service.yaml")); err != nil {
		t.Fatal(err)
	}

	err := validateSourceWorkingTree(root)
	if !errors.Is(err, errExternalSourceSymlink) {
		t.Fatalf("validateSourceWorkingTree error = %v, want symlink error", err)
	}
}

func TestCacheRejectsAggregateExternalSourceBudget(t *testing.T) {
	cache := NewCache(t.TempDir())
	for index := 0; index < 4; index++ {
		sourcePath := filepath.Join(cache.baseDir, "existing-"+string(rune('a'+index)))
		if err := os.Mkdir(sourcePath, 0o700); err != nil {
			t.Fatal(err)
		}
		payloadPath := filepath.Join(sourcePath, "payload")
		if err := os.WriteFile(payloadPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(payloadPath, externalSourceCacheLimit); err != nil {
			t.Fatal(err)
		}
	}

	stagingPath, err := cache.CreateStagingDir("candidate")
	if err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(stagingPath, "payload")
	if err := os.WriteFile(payloadPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(payloadPath, externalSourceCacheLimit); err != nil {
		t.Fatal(err)
	}

	err = cache.ValidatePromotionBudget("candidate", stagingPath)
	var resourceErr *sourceResourceError
	if !errors.As(err, &resourceErr) {
		t.Fatalf("ValidatePromotionBudget error = %v, want source resource error", err)
	}
}
