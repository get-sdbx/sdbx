package generator

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/get-sdbx/sdbx/internal/securefs"
)

// resolvePath resolves a path relative to the project's OutputDir if rel is
// relative; absolute paths are returned unchanged.
func (g *Generator) resolvePath(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(g.OutputDir, rel)
}

// configRoot returns the resolved absolute path to the configured config dir.
// If Config.ConfigPath is empty, falls back to "configs" under OutputDir.
func (g *Generator) configRoot() string {
	if g.configRootOverride != "" {
		return g.configRootOverride
	}
	base := g.Config.ConfigPath
	if base == "" {
		base = "configs"
	}
	return g.resolvePath(base)
}

// configPath returns an absolute path inside the configured config dir.
func (g *Generator) configPath(rel ...string) string {
	parts := append([]string{g.configRoot()}, rel...)
	return filepath.Join(parts...)
}

// secretsRoot returns the resolved absolute path to the configured secrets dir.
// If Config.SecretsPath is empty, falls back to "secrets" under OutputDir.
func (g *Generator) secretsRoot() string {
	if g.secretsRootOverride != "" {
		return g.secretsRootOverride
	}
	base := g.Config.SecretsPath
	if base == "" {
		base = "secrets"
	}
	return g.resolvePath(base)
}

// secretsPath returns an absolute path inside the configured secrets dir.
func (g *Generator) secretsPath(rel ...string) string {
	parts := append([]string{g.secretsRoot()}, rel...)
	return filepath.Join(parts...)
}

// projectPath returns an absolute path under the project OutputDir.
func (g *Generator) projectPath(rel ...string) string {
	parts := append([]string{g.OutputDir}, rel...)
	return filepath.Join(parts...)
}

// validateManagedPaths confines every relative managed root to OutputDir and
// rejects symlink traversal before generation starts. Absolute roots remain an
// explicit supported feature, but may not be filesystem roots or symlinks.
func (g *Generator) validateManagedPaths() error {
	projectRoot, err := filepath.Abs(g.OutputDir)
	if err != nil {
		return fmt.Errorf("resolve project directory: %w", err)
	}
	if filepath.Dir(projectRoot) == projectRoot {
		return fmt.Errorf("project directory must not be a filesystem root")
	}
	if err := rejectFinalSymlink(projectRoot); err != nil {
		return fmt.Errorf("unsafe project directory: %w", err)
	}

	managed := []struct {
		name       string
		configured string
		resolved   string
	}{
		{"config_path", g.Config.ConfigPath, g.configRoot()},
		{"data_path", g.Config.DataPath, g.resolvePath(g.Config.DataPath)},
		{"downloads_path", g.Config.DownloadsPath, g.resolvePath(g.Config.DownloadsPath)},
		{"media_path", g.Config.MediaPath, g.resolvePath(g.Config.MediaPath)},
		{"secrets_path", g.Config.SecretsPath, g.secretsRoot()},
	}
	for _, candidate := range managed {
		resolved, err := filepath.Abs(candidate.resolved)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", candidate.name, err)
		}
		if filepath.Dir(resolved) == resolved {
			return fmt.Errorf("%s must not resolve to a filesystem root", candidate.name)
		}
		if samePath(resolved, projectRoot) {
			return fmt.Errorf("%s must not resolve to the project root", candidate.name)
		}
		if filepath.IsAbs(candidate.configured) {
			if err := rejectFinalSymlink(resolved); err != nil {
				return fmt.Errorf("unsafe %s: %w", candidate.name, err)
			}
			continue
		}
		if err := securefs.RejectSymlinkTraversal(projectRoot, resolved); err != nil {
			return fmt.Errorf("unsafe %s: %w", candidate.name, err)
		}
	}
	return nil
}

func rejectFinalSymlink(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s must be a directory", path)
	}
	return nil
}

func samePath(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}
