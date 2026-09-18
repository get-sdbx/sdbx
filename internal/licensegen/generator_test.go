package licensegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindLicenseFilesUsesNearestPackageLicense(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested", "package")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		filepath.Join(root, "LICENSE"):           "root license",
		filepath.Join(root, "NOTICE"):            "root notice",
		filepath.Join(root, "nested", "LICENSE"): "nested license",
		filepath.Join(root, "nested", "NOTICE"):  "nested notice",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	paths, err := findLicenseFiles(nested, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 ||
		filepath.Base(paths[0]) != "LICENSE" ||
		filepath.Base(paths[1]) != "NOTICE" ||
		filepath.Dir(paths[0]) != filepath.Join(root, "nested") {
		t.Fatalf("unexpected nearest notice set: %v", paths)
	}
}

func TestFindLicenseFilesRejectsEscapingPackage(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if _, err := findLicenseFiles(outside, root); err == nil {
		t.Fatal("expected an escaping package directory to be rejected")
	}
}

func TestFindLicenseFilesIncludesPatentGrant(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"LICENSE", "NOTICE", "PATENTS", "PATENTS.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := findLicenseFiles(root, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 4 {
		t.Fatalf("expected license, notice and patent grants, got %v", paths)
	}
	for index, name := range []string{"LICENSE", "NOTICE", "PATENTS", "PATENTS.txt"} {
		if filepath.Base(paths[index]) != name {
			t.Fatalf("missing %s in %v", name, paths)
		}
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	files := map[string]noticeFile{
		"b": {Component: "second v1", Path: "LICENSE", Content: []byte("B")},
		"a": {Component: "first v1", Path: "COPYING", Content: []byte("A")},
	}
	first := string(render(files))
	second := string(render(files))
	if first != second {
		t.Fatal("render output is not deterministic")
	}
	if strings.Index(first, "Component: first v1") >
		strings.Index(first, "Component: second v1") {
		t.Fatal("render output is not sorted")
	}
}
