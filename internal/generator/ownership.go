package generator

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/get-sdbx/sdbx/internal/redact"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

type volumeOwnershipTarget struct {
	path string
	uid  int
	gid  int
}

// PrepareRuntimePermissions reapplies host ownership required by enabled
// non-root services. It makes `sdbx up` self-heal permissions after a
// transaction, restore, or manual directory recreation before Compose starts.
func (g *Generator) PrepareRuntimePermissions() error {
	graph, err := g.Plan()
	if err != nil {
		return err
	}
	return g.applyVolumeOwnershipWithPolicy(graph, true)
}

// applyVolumeOwnership chowns every volume host path that opted in via
// `chown: true` in its service definition. Used for images that run as a
// non-root user and need write access to a host directory that sdbx mkdir'd
// as root (e.g. filebrowser at UID 1000 writing to /database).
//
// Generation warns when a Linux chown is unavailable so a non-root user can
// still review the complete project. PrepareRuntimePermissions repeats the
// operation strictly before startup, where continuing would create a restart
// loop. Non-Linux development hosts skip chown; Docker Desktop owns the
// host-to-VM permission translation there.
func (g *Generator) applyVolumeOwnership(graph *registry.ResolutionGraph) error {
	return g.applyVolumeOwnershipWithPolicy(graph, false)
}

func (g *Generator) applyVolumeOwnershipWithPolicy(
	graph *registry.ResolutionGraph,
	strict bool,
) error {
	if g.deferVolumeOwnership {
		return nil
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	if g.Config == nil {
		return nil
	}

	for _, name := range graph.Order {
		resolved := graph.Services[name]
		if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
			continue
		}
		targets, pathsErr := g.ownershipVolumeTargets(resolved.FinalDefinition)
		if pathsErr != nil {
			return pathsErr
		}
		for _, target := range targets {
			ownershipRoot, managed, rootErr := g.volumeOwnershipRoot(target.path)
			if rootErr != nil {
				return rootErr
			}
			var chownErr error
			if managed {
				chownErr = securefs.ChownRealDirectoryAt(
					ownershipRoot,
					target.path,
					target.uid,
					target.gid,
				)
			} else {
				// Explicit host-mount + host-chown grants may target a path
				// outside SDBX-managed roots. Its exact directory is still
				// inode-pinned before ownership is applied.
				chownErr = securefs.ChownRealDirectory(
					target.path,
					target.uid,
					target.gid,
				)
			}
			if chownErr != nil {
				ownershipErr := fmt.Errorf(
					"chown %s to %d:%d: %s",
					redact.Text(target.path),
					target.uid,
					target.gid,
					redact.Text(chownErr.Error()),
				)
				if strict {
					return ownershipErr
				}
				fmt.Fprintf(os.Stderr, "warning: %s\n", ownershipErr)
			}
		}
	}
	return nil
}

func (g *Generator) ownershipVolumeTargets(
	definition *registry.ServiceDefinition,
) ([]volumeOwnershipTarget, error) {
	if definition == nil {
		return nil, fmt.Errorf("service definition is missing")
	}
	ctx := TemplateContext{
		Config: catalogTemplateConfig(g.Config, definition),
		Name:   definition.Metadata.Name,
	}
	targets := make([]volumeOwnershipTarget, 0, len(definition.Spec.Volumes))
	for index, volume := range definition.Spec.Volumes {
		if !volume.Chown {
			continue
		}
		matches, err := evalCatalogCondition(volume.When, ctx)
		if err != nil {
			return nil, fmt.Errorf(
				"evaluate %s ownership volume %d condition: %w",
				definition.Metadata.Name,
				index,
				err,
			)
		}
		if !matches {
			continue
		}
		hostPath, err := g.renderVolumeHostPath(volume.HostPath, definition)
		if err != nil {
			return nil, fmt.Errorf(
				"render %s ownership volume %d: %w",
				definition.Metadata.Name,
				index,
				err,
			)
		}
		uid := g.Config.PUID
		gid := g.Config.PGID
		if volume.ChownUID != 0 && volume.ChownGID != 0 {
			uid = volume.ChownUID
			gid = volume.ChownGID
		}
		targets = append(targets, volumeOwnershipTarget{
			path: hostPath,
			uid:  uid,
			gid:  gid,
		})
	}
	return targets, nil
}

func (g *Generator) volumeOwnershipRoot(hostPath string) (string, bool, error) {
	target, err := filepath.Abs(hostPath)
	if err != nil {
		return "", false, fmt.Errorf("resolve volume ownership target: %w", err)
	}
	candidates := []string{
		g.configRoot(),
		g.secretsRoot(),
		g.resolvePath(g.Config.DownloadsPath),
		g.resolvePath(g.Config.MediaPath),
		g.resolvePath(g.Config.DataPath),
		g.OutputDir,
	}
	roots := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		absolute, absErr := filepath.Abs(candidate)
		if absErr != nil {
			return "", false, fmt.Errorf(
				"resolve volume ownership root %s: %w",
				redact.Text(candidate),
				absErr,
			)
		}
		absolute = filepath.Clean(absolute)
		if _, exists := seen[absolute]; exists {
			continue
		}
		seen[absolute] = struct{}{}
		roots = append(roots, absolute)
	}
	sort.SliceStable(roots, func(i, j int) bool {
		return len(roots[i]) > len(roots[j])
	})
	target = filepath.Clean(target)
	for _, root := range roots {
		if pathWithinRoot(root, target) {
			return root, true, nil
		}
	}
	return "", false, nil
}

// renderVolumeHostPath evaluates the {{ .Config.X }} / {{ .Name }} templates
// in a volume hostPath the same way the compose generator does, then resolves
// it to an absolute filesystem path.
func (g *Generator) renderVolumeHostPath(
	raw string,
	definition *registry.ServiceDefinition,
) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("volume host path is empty")
	}
	if definition == nil {
		return "", fmt.Errorf("service definition is missing")
	}
	rendered, err := renderCatalogTemplate(raw, TemplateContext{
		Config: catalogTemplateConfig(g.Config, definition),
		Name:   definition.Metadata.Name,
	})
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(rendered) {
		return rendered, nil
	}
	return filepath.Join(g.OutputDir, rendered), nil
}
