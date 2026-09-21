package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/commandexec"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
	sdbxrouting "github.com/get-sdbx/sdbx/internal/routing"
	"github.com/get-sdbx/sdbx/internal/secrets"
	"github.com/get-sdbx/sdbx/internal/tui"
	"golang.org/x/sys/unix"
)

const initPreflightTimeout = 20 * time.Second

type initPreflightCheck struct {
	Name    string
	Message string
}

type initPreflightReport struct {
	Checks   []initPreflightCheck
	Warnings []string
	Compose  *generator.ComposeFile
}

var initDockerCommandOutput = func(ctx context.Context, args ...string) ([]byte, error) {
	return commandexec.CombinedOutput(ctx, 1<<20, nil, "docker", args...)
}

var (
	initTCPListen = net.Listen
	initUDPListen = net.ListenPacket
)

func runInitPreflight(
	ctx context.Context,
	cfg *config.Config,
	reg *registry.Registry,
	lock *registry.LockFile,
	graph *registry.ResolutionGraph,
	allowOccupiedPorts bool,
) (*initPreflightReport, error) {
	if cfg == nil || reg == nil || lock == nil || graph == nil {
		return nil, fmt.Errorf("configuration, registry, lock, and graph are required")
	}
	report := &initPreflightReport{}
	checkCommandVersion := func(
		name string,
		args []string,
		minMajor, minMinor int,
	) error {
		checkCtx, cancel := context.WithTimeout(ctx, initPreflightTimeout)
		defer cancel()
		output, err := initDockerCommandOutput(checkCtx, args...)
		if err != nil {
			return fmt.Errorf(
				"%s unavailable: %w: %s",
				name,
				err,
				redactCLIError(strings.TrimSpace(string(output))),
			)
		}
		version, err := firstVersion(string(output))
		if err != nil {
			return fmt.Errorf("%s returned an unrecognized version: %w", name, err)
		}
		if version[0] < minMajor || version[0] == minMajor && version[1] < minMinor {
			return fmt.Errorf(
				"%s %d.%d or newer is required; found %d.%d.%d",
				name,
				minMajor,
				minMinor,
				version[0],
				version[1],
				version[2],
			)
		}
		report.Checks = append(report.Checks, initPreflightCheck{
			Name:    name,
			Message: fmt.Sprintf("%d.%d.%d", version[0], version[1], version[2]),
		})
		return nil
	}
	if err := checkCommandVersion(
		"Docker Engine",
		[]string{"version", "--format", "{{.Server.Version}}"},
		24,
		0,
	); err != nil {
		return nil, err
	}
	if err := checkCommandVersion(
		"Docker Compose",
		[]string{"compose", "version", "--short"},
		5,
		0,
	); err != nil {
		return nil, err
	}
	if err := checkCommandVersion(
		"Docker Buildx",
		[]string{"buildx", "version"},
		0,
		10,
	); err != nil {
		return nil, err
	}
	pathSummary, err := checkInitManagedPaths(cfg)
	if err != nil {
		return nil, err
	}
	report.Checks = append(report.Checks, initPreflightCheck{
		Name:    "Managed paths",
		Message: pathSummary,
	})

	composeFile, err := generator.NewComposeGeneratorWithLock(cfg, reg, lock).Generate(graph)
	if err != nil {
		return nil, fmt.Errorf("build Compose preflight model: %w", err)
	}
	portWarnings, err := checkPublishedPorts(composeFile, allowOccupiedPorts)
	if err != nil {
		return nil, err
	}
	report.Checks = append(report.Checks, initPreflightCheck{
		Name:    "Host ports",
		Message: fmt.Sprintf("%d published binding(s) checked", countPublishedPorts(composeFile)),
	})
	report.Warnings = append(report.Warnings, portWarnings...)
	report.Checks = append(report.Checks,
		initPreflightCheck{
			Name:    "Catalog",
			Message: fmt.Sprintf("%d service definition(s) resolved", len(graph.Order)),
		},
		initPreflightCheck{
			Name:    "Images",
			Message: fmt.Sprintf("%d immutable image pin(s) resolved", len(lock.Services)),
		},
		initPreflightCheck{
			Name:    "Credentials",
			Message: initCredentialSummary(cfg),
		},
	)
	report.Compose = composeFile
	return report, nil
}

func checkInitManagedPaths(cfg *config.Config) (string, error) {
	if cfg.ProjectDir == "" {
		return "", fmt.Errorf("project directory is required for path preflight")
	}
	configured := []string{
		cfg.ConfigPath,
		cfg.DataPath,
		cfg.DownloadsPath,
		cfg.MediaPath,
		cfg.SecretsPath,
	}
	seen := make(map[string]struct{}, len(configured))
	for _, raw := range configured {
		target := raw
		if !filepath.IsAbs(target) {
			target = filepath.Join(cfg.ProjectDir, target)
		}
		target = filepath.Clean(target)
		if _, duplicate := seen[target]; duplicate {
			continue
		}
		seen[target] = struct{}{}

		existing := target
		for {
			info, err := os.Lstat(existing)
			if err == nil {
				if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
					return "", fmt.Errorf(
						"managed path %s has a non-directory or symlink ancestor %s",
						target,
						existing,
					)
				}
				if err := unix.Access(existing, unix.W_OK|unix.X_OK); err != nil {
					return "", fmt.Errorf(
						"managed path %s is not writable through %s: %w",
						target,
						existing,
						err,
					)
				}
				break
			}
			if !os.IsNotExist(err) {
				return "", fmt.Errorf("inspect managed path %s: %w", existing, err)
			}
			parent := filepath.Dir(existing)
			if parent == existing {
				return "", fmt.Errorf("managed path %s has no accessible ancestor", target)
			}
			existing = parent
		}
	}
	return fmt.Sprintf("%d unique root(s) are writable and symlink-safe", len(seen)), nil
}

func firstVersion(raw string) ([3]int, error) {
	var version [3]int
	start := -1
	for index, char := range raw {
		if char >= '0' && char <= '9' {
			start = index
			break
		}
	}
	if start < 0 {
		return version, fmt.Errorf("no numeric version in %q", strings.TrimSpace(raw))
	}
	parts := strings.FieldsFunc(raw[start:], func(char rune) bool {
		return char != '.' && (char < '0' || char > '9')
	})
	if len(parts) == 0 {
		return version, fmt.Errorf("no version components in %q", strings.TrimSpace(raw))
	}
	numbers := strings.Split(parts[0], ".")
	for index := 0; index < len(numbers) && index < len(version); index++ {
		value, err := strconv.Atoi(numbers[index])
		if err != nil {
			return version, err
		}
		version[index] = value
	}
	return version, nil
}

type publishedPort struct {
	Protocol string
	Host     string
	Port     int
	Service  string
}

func composePublishedPorts(compose *generator.ComposeFile) ([]publishedPort, error) {
	var ports []publishedPort
	for serviceName, service := range compose.Services {
		for _, raw := range service.Ports {
			binding, err := parsePublishedPort(raw)
			if err != nil {
				return nil, fmt.Errorf("service %s port %q: %w", serviceName, raw, err)
			}
			binding.Service = serviceName
			ports = append(ports, binding)
		}
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Port != ports[j].Port {
			return ports[i].Port < ports[j].Port
		}
		if ports[i].Protocol != ports[j].Protocol {
			return ports[i].Protocol < ports[j].Protocol
		}
		return ports[i].Service < ports[j].Service
	})
	return ports, nil
}

func parsePublishedPort(raw string) (publishedPort, error) {
	protocol := "tcp"
	binding := raw
	if slash := strings.LastIndex(binding, "/"); slash >= 0 {
		protocol = strings.ToLower(binding[slash+1:])
		binding = binding[:slash]
	}
	if protocol != "tcp" && protocol != "udp" {
		return publishedPort{}, fmt.Errorf("unsupported protocol %q", protocol)
	}
	containerSeparator := strings.LastIndex(binding, ":")
	if containerSeparator <= 0 || containerSeparator == len(binding)-1 {
		return publishedPort{}, fmt.Errorf("expected HOST_PORT:CONTAINER_PORT")
	}
	hostAndPort := binding[:containerSeparator]
	containerPort := binding[containerSeparator+1:]
	parsedContainerPort, err := strconv.Atoi(containerPort)
	if err != nil || parsedContainerPort < 1 || parsedContainerPort > 65535 {
		return publishedPort{}, fmt.Errorf("invalid container port %q", containerPort)
	}

	host := ""
	hostPort := hostAndPort
	if hostSeparator := strings.LastIndex(hostAndPort, ":"); hostSeparator >= 0 {
		host = strings.Trim(hostAndPort[:hostSeparator], "[]")
		hostPort = hostAndPort[hostSeparator+1:]
	}
	port, err := strconv.Atoi(hostPort)
	if err != nil || port < 1 || port > 65535 {
		return publishedPort{}, fmt.Errorf("invalid host port %q", hostPort)
	}
	return publishedPort{Protocol: protocol, Host: host, Port: port}, nil
}

func checkPublishedPorts(
	compose *generator.ComposeFile,
	allowOccupied bool,
) ([]string, error) {
	ports, err := composePublishedPorts(compose)
	if err != nil {
		return nil, err
	}
	seen := make([]publishedPort, 0, len(ports))
	var warnings []string
	for _, binding := range ports {
		for _, previous := range seen {
			if publishedPortsConflict(previous, binding) {
				return nil, fmt.Errorf(
					"published port conflict: %s and %s both require %s port %d on overlapping hosts",
					previous.Service,
					binding.Service,
					binding.Protocol,
					binding.Port,
				)
			}
		}
		seen = append(seen, binding)
		address := net.JoinHostPort(binding.Host, strconv.Itoa(binding.Port))
		if binding.Host == "" {
			address = ":" + strconv.Itoa(binding.Port)
		}
		var closer interface{ Close() error }
		switch binding.Protocol {
		case "tcp":
			closer, err = initTCPListen("tcp", address)
		case "udp":
			closer, err = initUDPListen("udp", address)
		}
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				warnings = append(warnings, fmt.Sprintf(
					"%s %s port %d availability could not be verified by the current user: permission denied",
					binding.Service,
					binding.Protocol,
					binding.Port,
				))
				continue
			}
			message := fmt.Sprintf(
				"%s requires occupied %s port %d",
				binding.Service,
				binding.Protocol,
				binding.Port,
			)
			if allowOccupied {
				warnings = append(warnings, message+"; allowed for existing-project regeneration")
				continue
			}
			return nil, fmt.Errorf("%s: %w", message, err)
		}
		if closeErr := closer.Close(); closeErr != nil {
			return nil, closeErr
		}
	}
	return warnings, nil
}

func publishedPortsConflict(left, right publishedPort) bool {
	if left.Protocol != right.Protocol || left.Port != right.Port {
		return false
	}
	return left.Host == right.Host || isWildcardHost(left.Host) || isWildcardHost(right.Host)
}

func isWildcardHost(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::"
}

func countPublishedPorts(compose *generator.ComposeFile) int {
	ports, err := composePublishedPorts(compose)
	if err != nil {
		return 0
	}
	return len(ports)
}

func initCredentialSummary(cfg *config.Config) string {
	pending := []string{}
	if cfg.VPNEnabled {
		pending = append(pending, "VPN provider credentials in the private Gluetun config")
	}
	if cfg.Expose.Mode == config.ExposeModeCloudflared {
		pending = append(pending, "tunnel token")
	}
	if cfg.PlexEnabled && cfg.Expose.Mode != config.ExposeModeLAN {
		pending = append(pending, "Plex claim token")
	}
	if len(pending) == 0 {
		return "admin credential ready; no provider credential required before first start"
	}
	return "admin credential ready; configure after init: " + strings.Join(pending, ", ")
}

func validateStagedCompose(
	parent context.Context,
	stageProject string,
) error {
	ctx, cancel := context.WithTimeout(parent, initPreflightTimeout)
	defer cancel()
	output, err := initDockerCommandOutput(
		ctx,
		"compose",
		"--project-directory",
		stageProject,
		"-f",
		stageProject+"/compose.yaml",
		"config",
		"--quiet",
		"--no-env-resolution",
		"--no-path-resolution",
	)
	if err != nil {
		return fmt.Errorf(
			"docker compose config failed: %w: %s",
			err,
			redactCLIError(strings.TrimSpace(string(output))),
		)
	}
	return nil
}

func printInitPreflight(report *initPreflightReport) {
	fmt.Println(tui.TitleStyle.Render("Preflight"))
	fmt.Println()
	for _, check := range report.Checks {
		fmt.Printf("  %s %-18s %s\n", tui.IconSuccess, check.Name, check.Message)
	}
	for _, warning := range report.Warnings {
		fmt.Printf("  %s %s\n", tui.IconWarning, warning)
	}
	fmt.Println()
}

func printInitPreview(
	cfg *config.Config,
	graph *registry.ResolutionGraph,
	lock *registry.LockFile,
	compose *generator.ComposeFile,
) {
	fmt.Println(tui.TitleStyle.Render("Deployment preview"))
	fmt.Println()
	fmt.Printf("  Exposure: %s  Routing: %s  Media: %s  VPN: %s\n",
		cfg.Expose.Mode,
		cfg.Routing.Strategy,
		selectedMediaServers(cfg),
		vpnPreview(cfg),
	)
	fmt.Printf("  Paths: config=%s  secrets=%s  downloads=%s  media=%s\n",
		cfg.ConfigPath,
		cfg.SecretsPath,
		cfg.DownloadsPath,
		cfg.MediaPath,
	)
	fmt.Println()
	fmt.Printf("  %-20s %-12s %-20s %s\n", "SERVICE", "AUTH", "NETWORKS", "ROUTE")
	fmt.Printf("  %s\n", strings.Repeat("─", 100))
	manualSecrets := make(map[string]struct{})
	for _, name := range graph.Order {
		resolved := graph.Services[name]
		if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
			continue
		}
		definition := resolved.FinalDefinition
		route := "internal only"
		if definition.Routing.Enabled {
			route = initServiceURL(cfg, definition)
		}
		auth := "-"
		if definition.Routing.Enabled {
			auth = string(definition.Routing.Auth.Mode)
		}
		networks := make([]string, 0, len(definition.Spec.Networking.Networks))
		for _, network := range definition.Spec.Networking.Networks {
			networks = append(networks, network.Name)
		}
		if len(networks) == 0 && definition.Spec.Networking.Mode != "" {
			networks = append(networks, definition.Spec.Networking.Mode)
		}
		var ports, mounts, composeSecrets []string
		if compose != nil {
			service := compose.Services[name]
			ports = service.Ports
			mounts = service.Volumes
			composeSecrets = service.Secrets
		}
		fmt.Printf(
			"  %-20s %-12s %-20s %s\n",
			name,
			auth,
			truncate(strings.Join(networks, ","), 20),
			route,
		)
		if len(ports) > 0 {
			fmt.Printf("    published ports: %s\n", strings.Join(ports, ", "))
		}
		if len(mounts) > 0 {
			fmt.Printf("    mounts: %s\n", strings.Join(mounts, ", "))
		}
		if len(composeSecrets) > 0 {
			fmt.Printf("    secrets: %s\n", strings.Join(composeSecrets, ", "))
		}
		for _, secret := range definition.Secrets {
			if secret.Type == "manual" && !secrets.IsConsoleProxySecret(secret.Name) {
				manualSecrets[secret.Name] = struct{}{}
			}
		}
	}
	fmt.Println()
	fmt.Printf("  Locked services: %d  Catalog: %s\n", len(lock.Services), truncate(lock.Metadata.CatalogDigest, 20))
	if len(manualSecrets) > 0 {
		names := make([]string, 0, len(manualSecrets))
		for name := range manualSecrets {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Printf("  Manual secrets after init: %s\n", strings.Join(names, ", "))
	}
	fmt.Println()
}

func initServiceURL(cfg *config.Config, definition *registry.ServiceDefinition) string {
	return sdbxrouting.URL(cfg, definition)
}

func uniqueResolutionWarnings(
	values []registry.ResolutionWarning,
) []registry.ResolutionWarning {
	seen := make(map[string]struct{}, len(values))
	result := make([]registry.ResolutionWarning, 0, len(values))
	for _, value := range values {
		key := value.Service + "\x00" + value.Field + "\x00" + value.Message
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func selectedMediaServers(cfg *config.Config) string {
	switch {
	case cfg.PlexEnabled && cfg.JellyfinEnabled:
		return "Plex + Jellyfin"
	case cfg.PlexEnabled:
		return "Plex"
	case cfg.JellyfinEnabled:
		return "Jellyfin"
	default:
		return "none"
	}
}

func vpnPreview(cfg *config.Config) string {
	if cfg.VPNEnabled {
		return fmt.Sprintf("protected via %s", cfg.VPNProvider)
	}
	return "disabled (host public IP)"
}
