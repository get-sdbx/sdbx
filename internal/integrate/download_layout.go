package integrate

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

// ManagedDownloadDirectories is the stable qBittorrent/Arr layout created by
// sdbx integrate. Existing files are never moved into these directories.
var ManagedDownloadDirectories = []string{
	"incomplete",
	"movies",
	"music",
	"other",
	"stash",
	"tv",
}

// PrepareDownloadLayout creates only missing managed directories. Existing
// directories keep their contents; symlinks and non-directories fail closed.
func PrepareDownloadLayout(cfg *config.Config, dryRun bool) error {
	if cfg == nil || cfg.DownloadsPath == "" {
		return fmt.Errorf("downloads path is required")
	}
	root := filepath.Clean(cfg.DownloadsPath)
	info, err := os.Lstat(root)
	if err != nil {
		if dryRun && os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect downloads root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("downloads root must be a real directory")
	}
	for _, name := range ManagedDownloadDirectories {
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("managed download path %s must be a real directory", name)
			}
			continue
		case !os.IsNotExist(err):
			return fmt.Errorf("inspect managed download path %s: %w", name, err)
		case dryRun:
			continue
		}
		if err := securefs.EnsureDir(path, 0o775); err != nil {
			return fmt.Errorf("create managed download path %s: %w", name, err)
		}
		if err := os.Chown(path, cfg.PUID, cfg.PGID); err != nil {
			return fmt.Errorf("set managed download path ownership for %s: %w", name, err)
		}
		// #nosec G302 -- download workers share the configured PUID/PGID and
		// require group write access; the downloads root is operator-managed.
		if err := os.Chmod(path, 0o775); err != nil {
			return fmt.Errorf("set managed download path permissions for %s: %w", name, err)
		}
	}
	return nil
}
