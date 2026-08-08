//go:build !darwin && !linux

package securefs

import (
	"io/fs"
	"os"
)

type fileOwnership struct{}

func ownershipFromInfo(fs.FileInfo) fileOwnership {
	return fileOwnership{}
}

// OwnedBy cannot inspect numeric ownership on this platform.
func OwnedBy(fs.FileInfo, int) bool {
	return true
}

func applyPathOwnership(string, fileOwnership) error {
	return nil
}

func applyFileOwnership(*os.File, fileOwnership) error {
	return nil
}

func applyExplicitFileOwnership(*os.File, int, int) error {
	return nil
}

func applyRootPathOwnership(*os.Root, string, fileOwnership) error {
	return nil
}
