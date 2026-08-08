//go:build darwin || linux

package securefs

import (
	"io/fs"
	"os"
	"syscall"
)

type fileOwnership struct {
	uid   int
	gid   int
	valid bool
}

func ownershipFromInfo(info fs.FileInfo) fileOwnership {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileOwnership{}
	}
	return fileOwnership{
		uid:   int(stat.Uid),
		gid:   int(stat.Gid),
		valid: true,
	}
}

// OwnedBy reports whether info records the expected numeric owner.
func OwnedBy(info fs.FileInfo, uid int) bool {
	ownership := ownershipFromInfo(info)
	return ownership.valid && ownership.uid == uid
}

func applyPathOwnership(path string, ownership fileOwnership) error {
	if os.Geteuid() != 0 || !ownership.valid {
		return nil
	}
	return os.Chown(path, ownership.uid, ownership.gid)
}

func applyFileOwnership(file *os.File, ownership fileOwnership) error {
	if os.Geteuid() != 0 || !ownership.valid {
		return nil
	}
	return file.Chown(ownership.uid, ownership.gid)
}

func applyExplicitFileOwnership(file *os.File, uid, gid int) error {
	if os.Geteuid() != 0 || uid < 0 || gid < 0 {
		return nil
	}
	return file.Chown(uid, gid)
}

func applyRootPathOwnership(root *os.Root, name string, ownership fileOwnership) error {
	if os.Geteuid() != 0 || !ownership.valid {
		return nil
	}
	return root.Chown(name, ownership.uid, ownership.gid)
}
