//go:build darwin || linux

package securefs

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// RenameBaseAt atomically moves one base-name entry between two pinned
// directories without re-resolving either parent pathname.
func RenameBaseAt(
	source *os.Root,
	sourceName string,
	destination *os.Root,
	destinationName string,
) error {
	if source == nil || destination == nil {
		return fmt.Errorf("rename roots are required")
	}
	if !validBaseName(sourceName) || !validBaseName(destinationName) {
		return fmt.Errorf("rename paths must be base filenames")
	}
	sourceDirectory, err := source.Open(".")
	if err != nil {
		return err
	}
	defer sourceDirectory.Close()
	destinationDirectory, err := destination.Open(".")
	if err != nil {
		return err
	}
	defer destinationDirectory.Close()
	return unix.Renameat(
		int(sourceDirectory.Fd()),
		sourceName,
		int(destinationDirectory.Fd()),
		destinationName,
	)
}

func validBaseName(name string) bool {
	return name != "" &&
		name != "." &&
		filepath.IsLocal(name) &&
		filepath.Base(name) == name
}
