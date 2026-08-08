//go:build darwin || linux

package securefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenameBaseAtUsesPinnedDirectoryInodes(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "source")
	destinationPath := filepath.Join(root, "destination")
	movedDestinationPath := filepath.Join(root, "destination-moved")
	decoyPath := filepath.Join(root, "decoy")
	for _, directory := range []string{sourcePath, destinationPath, decoyPath} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "state"), []byte("trusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, _, err := OpenVerifiedRoot(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, _, err := OpenVerifiedRoot(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()

	if err := os.Rename(destinationPath, movedDestinationPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoyPath, destinationPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := RenameBaseAt(source, "state", destination, "state"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(movedDestinationPath, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "trusted" {
		t.Fatalf("pinned destination content = %q", data)
	}
	if _, err := os.Stat(filepath.Join(decoyPath, "state")); !os.IsNotExist(err) {
		t.Fatalf("rename followed replacement symlink, stat err=%v", err)
	}
}
