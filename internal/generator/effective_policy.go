package generator

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/get-sdbx/sdbx/internal/registry"
)

const dockerSocketPath = "/var/run/docker.sock"

var serviceNetworkModePattern = regexp.MustCompile(
	`^service:[a-z0-9][a-z0-9-]{0,62}$`,
)

var effectiveContainerHostnamePattern = regexp.MustCompile(
	`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`,
)

func validateEffectiveContainerHostname(hostname string) error {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return nil
	}
	if len(hostname) > 63 || !effectiveContainerHostnamePattern.MatchString(hostname) {
		return fmt.Errorf("must be a lowercase RFC 1123 hostname label")
	}
	return nil
}

func validateEffectiveContainerUser(user string) error {
	if user == "" {
		return nil
	}
	parts := strings.Split(user, ":")
	if len(parts) > 2 {
		return fmt.Errorf("must be a non-root numeric UID or UID:GID")
	}
	for index, part := range parts {
		value, err := strconv.ParseUint(part, 10, 31)
		if err != nil || value == 0 {
			label := "UID"
			if index == 1 {
				label = "GID"
			}
			return fmt.Errorf("%s must be a non-root decimal integer", label)
		}
	}
	return nil
}

type effectiveCatalogRoot struct {
	path       string
	permission string
}

func validateEffectiveVolume(
	def *registry.ServiceDefinition,
	ctx TemplateContext,
	volume registry.VolumeMount,
	hostPath string,
	containerPath string,
) (string, string, error) {
	if strings.ContainsAny(hostPath, "\x00\r\n:") {
		return "", "", fmt.Errorf(
			"host path contains a forbidden control character or mount separator",
		)
	}
	if strings.ContainsAny(containerPath, "\x00\r\n:") {
		return "", "", fmt.Errorf(
			"container path contains a forbidden control character or mount separator",
		)
	}

	effectiveHostPath, err := resolveCatalogHostPath(ctx.Config.ProjectDir, hostPath)
	if err != nil {
		return "", "", err
	}
	canonicalHostPath, err := canonicalizeCatalogPath(effectiveHostPath)
	if err != nil {
		return "", "", fmt.Errorf("canonicalize effective host path: %w", err)
	}
	effectiveContainerPath := path.Clean(containerPath)
	if !path.IsAbs(effectiveContainerPath) || effectiveContainerPath != containerPath {
		return "", "", fmt.Errorf(
			"container path %q must be a clean absolute path",
			containerPath,
		)
	}

	hostIsDockerSocket := isEffectiveDockerSocketPath(
		effectiveHostPath,
		canonicalHostPath,
	)
	containerIsDockerSocket := effectiveContainerPath == dockerSocketPath
	if hostIsDockerSocket || containerIsDockerSocket {
		return "", "", fmt.Errorf("effective Docker socket mounts are not supported")
	}

	requiredPermission, err := effectiveHostPathPermission(ctx, canonicalHostPath)
	if err != nil {
		return "", "", err
	}
	if !declaresCatalogPermission(def, requiredPermission) {
		return "", "", fmt.Errorf(
			"effective host path %q requires catalog permission %q",
			canonicalHostPath,
			requiredPermission,
		)
	}
	// Do not emit effectiveHostPath here. Relative bind mounts intentionally
	// remain relative to the generated compose.yaml, while authorization is
	// evaluated against their canonical project-relative destination above.
	return hostPath, effectiveContainerPath, nil
}

func validateEffectiveNetworkMode(
	def *registry.ServiceDefinition,
	networkMode string,
) error {
	switch {
	case networkMode == "", networkMode == "bridge":
		return nil
	case networkMode == "host":
		if !declaresCatalogPermission(def, registry.PermissionHostNetwork) {
			return fmt.Errorf(
				"effective host network mode requires catalog permission %q",
				registry.PermissionHostNetwork,
			)
		}
		return nil
	case serviceNetworkModePattern.MatchString(networkMode):
		target := strings.TrimPrefix(networkMode, "service:")
		permission := "service-network:" + target
		if !declaresCatalogPermission(def, permission) {
			return fmt.Errorf(
				"effective service network mode requires catalog permission %q",
				permission,
			)
		}
		return nil
	default:
		return fmt.Errorf(
			"effective network mode %q is not an allowed typed mode",
			networkMode,
		)
	}
}

func validateEffectiveEnvFile(
	def *registry.ServiceDefinition,
	ctx TemplateContext,
	envFile string,
) (string, error) {
	if envFile == "" {
		return "", fmt.Errorf("environment file path is required")
	}
	if strings.ContainsAny(envFile, "\x00\r\n") {
		return "", fmt.Errorf("environment file path contains a forbidden control character")
	}
	effectivePath, err := resolveCatalogHostPath(ctx.Config.ProjectDir, envFile)
	if err != nil {
		return "", err
	}
	canonicalPath, err := canonicalizeCatalogPath(effectivePath)
	if err != nil {
		return "", fmt.Errorf("canonicalize effective environment file path: %w", err)
	}
	requiredPermission, err := effectiveHostPathPermission(ctx, canonicalPath)
	if err != nil {
		return "", err
	}
	if !declaresCatalogPermission(def, requiredPermission) {
		return "", fmt.Errorf(
			"effective environment file path %q requires catalog permission %q",
			canonicalPath,
			requiredPermission,
		)
	}
	return envFile, nil
}

func validateEffectiveNetworkMembership(
	def *registry.ServiceDefinition,
	network string,
) error {
	permission := "network:" + network
	if !declaresCatalogPermission(def, permission) {
		return fmt.Errorf(
			"effective network membership %q requires catalog permission %q",
			network,
			permission,
		)
	}
	return nil
}

func effectiveHostPathPermission(
	ctx TemplateContext,
	effectiveHostPath string,
) (string, error) {
	projectRoot, err := resolveCatalogProjectRoot(ctx.Config.ProjectDir)
	if err != nil {
		return "", err
	}
	rootSpecs := []effectiveCatalogRoot{
		{path: ctx.Config.SecretsPath, permission: registry.PermissionSecretsPath},
		{path: ctx.Config.ConfigPath, permission: registry.PermissionConfigPath},
		{path: ctx.Config.DownloadsPath, permission: registry.PermissionDownloads},
		{path: ctx.Config.MediaPath, permission: registry.PermissionMediaPath},
		{path: ctx.Config.DataPath, permission: registry.PermissionDataPath},
		{path: projectRoot, permission: registry.PermissionProjectPath},
	}
	roots := make([]effectiveCatalogRoot, 0, len(rootSpecs))
	for _, root := range rootSpecs {
		if root.path == "" {
			continue
		}
		resolved, resolveErr := resolveCatalogHostPath(projectRoot, root.path)
		if resolveErr != nil {
			return "", resolveErr
		}
		resolved, resolveErr = canonicalizeCatalogPath(resolved)
		if resolveErr != nil {
			return "", fmt.Errorf(
				"canonicalize catalog permission root %q: %w",
				root.path,
				resolveErr,
			)
		}
		roots = append(roots, effectiveCatalogRoot{
			path:       resolved,
			permission: root.permission,
		})
	}
	sort.SliceStable(roots, func(i, j int) bool {
		return len(roots[i].path) > len(roots[j].path)
	})
	for _, root := range roots {
		if pathWithinRoot(root.path, effectiveHostPath) {
			return root.permission, nil
		}
	}
	return registry.PermissionHostMount, nil
}

func resolveCatalogProjectRoot(projectDir string) (string, error) {
	if projectDir == "" {
		projectDir = "."
	}
	absolute, err := filepath.Abs(projectDir)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	return filepath.Clean(absolute), nil
}

func resolveCatalogHostPath(projectDir string, hostPath string) (string, error) {
	if hostPath == "" {
		return "", fmt.Errorf("host path is required")
	}
	if filepath.IsAbs(hostPath) {
		return filepath.Clean(hostPath), nil
	}
	projectRoot, err := resolveCatalogProjectRoot(projectDir)
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Join(projectRoot, hostPath)), nil
}

// canonicalizeCatalogPath resolves every existing symlink component while
// preserving a nonexistent suffix. This models the effective bind-mount
// destination without requiring generation to create catalog-requested paths.
func canonicalizeCatalogPath(target string) (string, error) {
	target = filepath.Clean(target)
	current := target
	var suffix []string
	for {
		_, err := os.Lstat(current)
		switch {
		case err == nil:
			resolved, evalErr := filepath.EvalSymlinks(current)
			if evalErr != nil {
				return "", evalErr
			}
			if len(suffix) > 0 {
				resolvedInfo, statErr := os.Stat(resolved)
				if statErr != nil {
					return "", statErr
				}
				if !resolvedInfo.IsDir() {
					return "", fmt.Errorf(
						"existing path component %q is not a directory",
						current,
					)
				}
			}
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			absolute, absErr := filepath.Abs(resolved)
			if absErr != nil {
				return "", absErr
			}
			return filepath.Clean(absolute), nil
		case !os.IsNotExist(err):
			return "", err
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for %q", target)
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func isEffectiveDockerSocketPath(lexicalPath, canonicalPath string) bool {
	knownPaths := []string{dockerSocketPath, "/run/docker.sock"}
	for _, knownPath := range knownPaths {
		if lexicalPath == knownPath {
			return true
		}
		canonicalKnownPath, err := canonicalizeCatalogPath(knownPath)
		if err == nil && canonicalPath == canonicalKnownPath {
			return true
		}
	}
	return false
}

func pathWithinRoot(root string, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func declaresCatalogPermission(
	def *registry.ServiceDefinition,
	permission string,
) bool {
	for _, declared := range def.Permissions {
		if declared == permission {
			return true
		}
	}
	return false
}
