// Package doctor provides health checks for sdbx.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	sdbxcloudflare "github.com/get-sdbx/sdbx/internal/cloudflare"
	"github.com/get-sdbx/sdbx/internal/config"
	sdbxdocker "github.com/get-sdbx/sdbx/internal/docker"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
	sdbxsecrets "github.com/get-sdbx/sdbx/internal/secrets"
	"github.com/get-sdbx/sdbx/internal/securefs"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	checkTimeout          = 5 * time.Second
	maxProjectConfigSize  = 1 << 20
	maxDoctorConfigSize   = 1 << 20
	cloudflareDNSEndpoint = "https://cloudflare-dns.com/dns-query"
	maxDNSResponseSize    = 64 << 10
	publicDNSCacheTTL     = time.Minute
)

type publicDNSCacheEntry struct {
	addresses []netip.Addr
	expires   time.Time
}

var publicDNSCache = struct {
	sync.Mutex
	entries map[string]publicDNSCacheEntry
}{entries: make(map[string]publicDNSCacheEntry)}

// Check represents a single diagnostic check
type Check struct {
	Name        string
	Description string
	Status      CheckStatus
	Message     string
	Duration    time.Duration
}

// CheckStatus represents the result of a check
type CheckStatus int

const (
	StatusPending CheckStatus = iota
	StatusRunning
	StatusPassed
	StatusWarning
	StatusFailed
)

// Doctor runs all diagnostic checks
type Doctor struct {
	ProjectDir      string
	Config          *config.Config
	Graph           *registry.ResolutionGraph
	ComposeModel    *generator.ComposeFile
	Checks          []Check
	vpnEgress       func(context.Context) (string, error)
	composePS       func(context.Context) ([]sdbxdocker.Service, error)
	cloudflareProbe func(context.Context, string) (int, bool, error)
}

// NewDoctor creates a new Doctor instance
func NewDoctor(projectDir string) *Doctor {
	doctor := &Doctor{
		ProjectDir: projectDir,
		Checks:     make([]Check, 0),
	}
	doctor.vpnEgress = func(ctx context.Context) (string, error) {
		compose := sdbxdocker.NewCompose(doctor.ProjectDir)
		return compose.Exec(
			ctx,
			"gluetun",
			"wget",
			"-qO-",
			"https://api.ipify.org",
		)
	}
	doctor.composePS = func(ctx context.Context) ([]sdbxdocker.Service, error) {
		return sdbxdocker.NewCompose(doctor.ProjectDir).PS(ctx)
	}
	doctor.cloudflareProbe = probeCloudflareRoute
	return doctor
}

// NewProjectDoctor constructs diagnostics from the exact verified graph and
// generated Compose model used by operational commands.
func NewProjectDoctor(
	projectDir string,
	cfg *config.Config,
	graph *registry.ResolutionGraph,
	composeModel *generator.ComposeFile,
) *Doctor {
	doctor := NewDoctor(projectDir)
	doctor.Config = cfg
	doctor.Graph = graph
	doctor.ComposeModel = composeModel
	return doctor
}

// RunAll executes all checks and returns results
func (d *Doctor) RunAll(ctx context.Context) []Check {
	d.Checks = d.Checks[:0]
	checks := []struct {
		name string
		fn   func(context.Context) (bool, string)
	}{
		{"Docker version", d.checkDockerVersion},
		{"Docker Compose version", d.checkComposeVersion},
		{"Disk space", d.checkDiskSpace},
		{"File permissions", d.checkPermissions},
		{"Required ports", d.checkPorts},
		{"Docker daemon", d.checkDockerDaemon},
		{"Service health", d.checkServiceHealth},
		{"Project files", d.checkProjectFiles},
		{"Configured paths", d.checkConfiguredPaths},
		{"*arr auth consistency", d.checkArrAuth},
		{"Secrets configured", d.checkSecrets},
		{"Cloudflare routing", d.checkCloudflareRouting},
		{"VPN connectivity", d.CheckVPN},
	}

	for _, c := range checks {
		check := Check{
			Name:   c.name,
			Status: StatusRunning,
		}

		start := time.Now()
		checkCtx, cancel := context.WithTimeout(ctx, checkTimeout)
		passed, message := c.fn(checkCtx)
		cancel()
		check.Duration = time.Since(start)
		check.Message = message

		if passed {
			check.Status = StatusPassed
		} else {
			check.Status = StatusFailed
		}

		d.Checks = append(d.Checks, check)
	}

	return d.Checks
}

type cloudflareProbeResult struct {
	url        string
	statusCode int
	atEdge     bool
	err        error
}

func (d *Doctor) checkCloudflareRouting(
	ctx context.Context,
) (bool, string) {
	if d.Config == nil ||
		d.Config.Expose.Mode != config.ExposeModeCloudflared {
		return true, "Not enabled"
	}
	plan, err := sdbxcloudflare.BuildPlan(d.Config, d.Graph)
	if err != nil {
		return false, err.Error()
	}
	if len(plan.URLs) == 0 {
		return false, "No public routes are configured"
	}

	results := make(chan cloudflareProbeResult, len(plan.URLs))
	for _, url := range plan.URLs {
		go func(target string) {
			statusCode, atEdge, probeErr := d.cloudflareProbe(ctx, target)
			results <- cloudflareProbeResult{
				url:        target,
				statusCode: statusCode,
				atEdge:     atEdge,
				err:        probeErr,
			}
		}(url)
	}

	var problems []string
	for range plan.URLs {
		result := <-results
		switch {
		case result.err != nil:
			problems = append(
				problems,
				fmt.Sprintf("%s unreachable: %v", result.url, result.err),
			)
		case !result.atEdge:
			problems = append(
				problems,
				result.url+" did not traverse the Cloudflare edge",
			)
		case result.statusCode == http.StatusNotFound:
			problems = append(
				problems,
				result.url+" returned 404; reconcile 'sdbx tunnel routes'",
			)
		case result.statusCode >= http.StatusInternalServerError:
			problems = append(
				problems,
				fmt.Sprintf(
					"%s returned upstream status %d",
					result.url,
					result.statusCode,
				),
			)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return false, strings.Join(problems, "; ")
	}
	return true, fmt.Sprintf(
		"Public routes reachable through Cloudflare: %d; tunnel targets were not checked",
		len(plan.URLs),
	)
}

func probeCloudflareRoute(
	ctx context.Context,
	target string,
) (int, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, false, err
	}
	request.Header.Set("User-Agent", "sdbx-doctor/1")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(
		ctx context.Context,
		network, address string,
	) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) != nil {
			return (&net.Dialer{Timeout: checkTimeout}).DialContext(
				ctx,
				network,
				address,
			)
		}
		addresses, err := resolvePublicDNS(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, resolved := range addresses {
			connection, dialErr := (&net.Dialer{Timeout: checkTimeout}).DialContext(
				ctx,
				network,
				net.JoinHostPort(resolved.String(), port),
			)
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(
			_ *http.Request,
			_ []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, false, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode,
		response.Header.Get("CF-Ray") != "",
		nil
}

func resolvePublicDNS(ctx context.Context, hostname string) ([]netip.Addr, error) {
	addresses, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip", hostname)
	if public := publicInternetAddresses(addresses); len(public) > 0 {
		return public, nil
	}

	publicDNSCache.Lock()
	defer publicDNSCache.Unlock()
	if cached, ok := publicDNSCache.entries[hostname]; ok &&
		time.Now().Before(cached.expires) {
		return append([]netip.Addr(nil), cached.addresses...), nil
	}
	public, err := lookupCloudflareDNS(ctx, hostname)
	if err != nil {
		if lookupErr != nil {
			return nil, fmt.Errorf("resolve public hostname: %w", lookupErr)
		}
		return nil, err
	}
	publicDNSCache.entries[hostname] = publicDNSCacheEntry{
		addresses: append([]netip.Addr(nil), public...),
		expires:   time.Now().Add(publicDNSCacheTTL),
	}
	return public, nil
}

func publicInternetAddresses(addresses []netip.Addr) []netip.Addr {
	public := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || !address.IsGlobalUnicast() ||
			address.IsPrivate() || address.IsLoopback() ||
			address.IsLinkLocalUnicast() {
			continue
		}
		public = append(public, address)
	}
	sort.SliceStable(public, func(left, right int) bool {
		return public[left].Is4() && !public[right].Is4()
	})
	return public
}

func lookupCloudflareDNS(ctx context.Context, hostname string) ([]netip.Addr, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	addresses := make([]netip.Addr, 0, 4)
	for _, queryType := range []string{"A", "AAAA"} {
		endpoint := cloudflareDNSEndpoint + "?name=" +
			url.QueryEscape(hostname) + "&type=" + queryType
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/dns-json")
		response, err := client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("query Cloudflare DNS: %w", err)
		}
		var payload struct {
			Status int `json:"Status"`
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		decodeErr := json.NewDecoder(
			io.LimitReader(response.Body, maxDNSResponseSize),
		).Decode(&payload)
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Cloudflare DNS returned HTTP %d", response.StatusCode)
		}
		if decodeErr != nil {
			return nil, fmt.Errorf("decode Cloudflare DNS response: %w", decodeErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close Cloudflare DNS response: %w", closeErr)
		}
		if payload.Status != 0 {
			return nil, fmt.Errorf("Cloudflare DNS returned status %d", payload.Status)
		}
		for _, answer := range payload.Answer {
			address, parseErr := netip.ParseAddr(answer.Data)
			if parseErr == nil {
				addresses = append(addresses, address)
			}
		}
	}
	public := publicInternetAddresses(addresses)
	if len(public) == 0 {
		return nil, fmt.Errorf("Cloudflare DNS returned no public address")
	}
	return public, nil
}

// checkDockerVersion verifies Docker is installed and version is sufficient
func (d *Doctor) checkDockerVersion(ctx context.Context) (bool, string) {
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	output, err := cmd.Output()
	if err != nil {
		return false, "Docker not found or not running"
	}

	version := strings.TrimSpace(string(output))
	// Parse major version
	parts := strings.Split(version, ".")
	if len(parts) < 1 {
		return false, "Could not parse Docker version"
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, "Could not parse Docker version"
	}

	if major < 24 {
		return false, fmt.Sprintf("Docker %s < 24.0 (minimum required)", version)
	}

	return true, fmt.Sprintf("%s ≥ 24.0", version)
}

// checkComposeVersion verifies Docker Compose v2 is available
func (d *Doctor) checkComposeVersion(ctx context.Context) (bool, string) {
	cmd := exec.CommandContext(ctx, "docker", "compose", "version", "--short")
	output, err := cmd.Output()
	if err != nil {
		return false, "Docker Compose not found"
	}

	version := strings.TrimSpace(string(output))
	// Remove 'v' prefix if present
	version = strings.TrimPrefix(version, "v")

	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false, "Could not parse Compose version"
	}

	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])

	if major < 2 || (major == 2 && minor < 35) {
		return false, fmt.Sprintf("Compose %s < 2.35 (minimum required)", version)
	}

	return true, fmt.Sprintf("%s ≥ 2.35", version)
}

// checkDiskSpace verifies sufficient disk space
func (d *Doctor) checkDiskSpace(_ context.Context) (bool, string) {
	var stat syscall.Statfs_t
	path := d.ProjectDir
	if path == "" {
		path = "."
	}

	if err := syscall.Statfs(path, &stat); err != nil {
		return false, "Could not check disk space"
	}

	// Calculate free space in GB
	// Use explicit conversion to avoid integer overflow
	blockSize := stat.Bsize
	if blockSize < 0 {
		return false, "Invalid block size"
	}
	freeGB := float64(stat.Bavail) * float64(blockSize) / (1024 * 1024 * 1024)

	if freeGB < 10 {
		return false, fmt.Sprintf("%.1f GB free (< 10 GB minimum)", freeGB)
	}

	return true, fmt.Sprintf("%.1f GB free", freeGB)
}

// checkPermissions verifies file permissions
func (d *Doctor) checkPermissions(_ context.Context) (bool, string) {
	testFile, err := os.CreateTemp(d.ProjectDir, ".sdbx-permission-check-*")
	if err != nil {
		return false, "Cannot write to project directory"
	}
	testPath := testFile.Name()
	if err := testFile.Close(); err != nil {
		return false, "Cannot close project write check"
	}
	if err := os.Remove(testPath); err != nil {
		return false, "Cannot clean up project write check"
	}

	// Check UID/GID
	if runtime.GOOS != "windows" {
		uid := os.Getuid()
		gid := os.Getgid()
		return true, fmt.Sprintf("UID/GID %d:%d", uid, gid)
	}

	return true, "OK"
}

// checkPorts verifies required ports are available
func (d *Doctor) checkPorts(ctx context.Context) (bool, string) {
	if d.ComposeModel == nil {
		return d.checkLegacyPorts(ctx)
	}
	bindings, err := doctorPublishedPorts(d.ComposeModel)
	if err != nil {
		return false, err.Error()
	}
	running := make(map[string]bool)
	if containers, err := d.composePS(ctx); err == nil {
		for _, container := range containers {
			if container.Running {
				running[container.Service] = true
			}
		}
	}
	var conflicts []string
	for _, binding := range bindings {
		address := net.JoinHostPort(binding.Host, strconv.Itoa(binding.Port))
		if binding.Host == "" {
			address = ":" + strconv.Itoa(binding.Port)
		}
		var listener interface{ Close() error }
		switch binding.Protocol {
		case "tcp":
			listener, err = net.Listen("tcp", address)
		case "udp":
			listener, err = net.ListenPacket("udp", address)
		}
		if err == nil {
			if closeErr := listener.Close(); closeErr != nil {
				return false, closeErr.Error()
			}
			continue
		}
		if !running[binding.Service] {
			conflicts = append(
				conflicts,
				fmt.Sprintf("%s %s/%d", binding.Service, binding.Protocol, binding.Port),
			)
		}
	}
	if len(conflicts) > 0 {
		return false, "Ports occupied outside their active services: " + strings.Join(conflicts, ", ")
	}
	return true, fmt.Sprintf("Published ports available or already used by SDBX: %d", len(bindings))
}

func (d *Doctor) checkLegacyPorts(ctx context.Context) (bool, string) {
	ports := []int{80, 443}
	var inUse []int
	for _, port := range ports {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			inUse = append(inUse, port)
			continue
		}
		_ = listener.Close()
	}
	if len(inUse) > 0 && !d.isSDBXRunning(ctx) {
		return false, fmt.Sprintf("Ports in use: %v", inUse)
	}
	return true, "Legacy host-port fallback checked"
}

type doctorPortBinding struct {
	Service  string
	Protocol string
	Host     string
	Port     int
}

func doctorPublishedPorts(
	compose *generator.ComposeFile,
) ([]doctorPortBinding, error) {
	var bindings []doctorPortBinding
	for serviceName, service := range compose.Services {
		for _, raw := range service.Ports {
			binding, err := parseDoctorPublishedPort(raw)
			if err != nil {
				return nil, fmt.Errorf("%s port %q: %w", serviceName, raw, err)
			}
			binding.Service = serviceName
			bindings = append(bindings, binding)
		}
	}
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].Port != bindings[j].Port {
			return bindings[i].Port < bindings[j].Port
		}
		if bindings[i].Protocol != bindings[j].Protocol {
			return bindings[i].Protocol < bindings[j].Protocol
		}
		return bindings[i].Service < bindings[j].Service
	})
	return bindings, nil
}

func parseDoctorPublishedPort(raw string) (doctorPortBinding, error) {
	protocol := "tcp"
	value := raw
	if slash := strings.LastIndex(value, "/"); slash >= 0 {
		protocol = strings.ToLower(value[slash+1:])
		value = value[:slash]
	}
	if protocol != "tcp" && protocol != "udp" {
		return doctorPortBinding{}, fmt.Errorf("unsupported protocol %q", protocol)
	}
	containerSeparator := strings.LastIndex(value, ":")
	if containerSeparator <= 0 || containerSeparator == len(value)-1 {
		return doctorPortBinding{}, fmt.Errorf("expected HOST_PORT:CONTAINER_PORT")
	}
	hostAndPort := value[:containerSeparator]
	containerPort, err := strconv.Atoi(value[containerSeparator+1:])
	if err != nil || containerPort < 1 || containerPort > 65535 {
		return doctorPortBinding{}, fmt.Errorf("invalid container port")
	}
	host := ""
	hostPort := hostAndPort
	if hostSeparator := strings.LastIndex(hostAndPort, ":"); hostSeparator >= 0 {
		host = strings.Trim(hostAndPort[:hostSeparator], "[]")
		hostPort = hostAndPort[hostSeparator+1:]
	}
	port, err := strconv.Atoi(hostPort)
	if err != nil || port < 1 || port > 65535 {
		return doctorPortBinding{}, fmt.Errorf("invalid host port %q", hostPort)
	}
	return doctorPortBinding{
		Protocol: protocol,
		Host:     host,
		Port:     port,
	}, nil
}

// isSDBXRunning checks if the main proxy container is running
func (d *Doctor) isSDBXRunning(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "sdbx-traefik")
}

// checkDockerDaemon verifies Docker daemon is running
func (d *Doctor) checkDockerDaemon(ctx context.Context) (bool, string) {
	cmd := exec.CommandContext(ctx, "docker", "info")
	if err := cmd.Run(); err != nil {
		return false, "Docker daemon not running"
	}
	return true, "Running"
}

func (d *Doctor) checkServiceHealth(ctx context.Context) (bool, string) {
	if d.Graph == nil {
		return true, "Not applicable outside an initialized project"
	}
	containers, err := d.composePS(ctx)
	if err != nil {
		return false, fmt.Sprintf("Could not inspect active Compose services: %v", err)
	}
	byService := make(map[string]sdbxdocker.Service, len(containers))
	for _, container := range containers {
		if container.Service != "" {
			byService[container.Service] = container
		}
	}
	var problems []string
	for _, name := range d.Graph.Order {
		resolved := d.Graph.Services[name]
		if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
			continue
		}
		container, present := byService[name]
		switch {
		case !present:
			problems = append(problems, name+" missing")
		case !container.Running:
			problems = append(problems, name+" "+container.Status)
		case container.Health == "unhealthy":
			problems = append(problems, name+" unhealthy")
		}
	}
	if len(problems) > 0 {
		return false, strings.Join(problems, ", ")
	}
	return true, fmt.Sprintf("%d active service(s) running", len(d.Graph.Order))
}

// checkProjectFiles verifies required project files exist
func (d *Doctor) checkProjectFiles(_ context.Context) (bool, string) {
	required := []string{".sdbx.yaml", ".sdbx.lock", "compose.yaml", ".env"}
	var missing []string

	for _, file := range required {
		path := filepath.Join(d.ProjectDir, file)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			missing = append(missing, file)
		} else if err != nil ||
			info.Mode()&os.ModeSymlink != 0 ||
			!info.Mode().IsRegular() {
			missing = append(missing, file+" (not a regular file)")
		}
	}

	if len(missing) > 0 {
		return false, fmt.Sprintf("Missing: %s", strings.Join(missing, ", "))
	}

	return true, "All present"
}

// checkSecrets verifies secrets are configured
func (d *Doctor) checkSecrets(_ context.Context) (bool, string) {
	secretsDir := d.resolveProjectPath(d.configuredSecretsPath())
	dirInfo, err := os.Lstat(secretsDir)
	if os.IsNotExist(err) {
		return false, "Secrets directory not found"
	}
	if err != nil {
		return false, "Secrets directory could not be inspected"
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return false, "Secrets path is not a real directory"
	}
	if dirInfo.Mode().Perm()&0o077 != 0 {
		return false, "Secrets directory is accessible by group or other users"
	}

	required := d.requiredSecretFiles()
	var problems []string
	for _, secret := range required {
		path := filepath.Join(secretsDir, secret)
		info, err := os.Lstat(path)
		switch {
		case err != nil:
			problems = append(problems, secret+" missing")
		case info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular():
			problems = append(problems, secret+" is not a regular file")
		case sdbxsecrets.ContainerReadable(secret) &&
			!containerReadableSecretIsProtected(dirInfo, info):
			problems = append(
				problems,
				secret+" must be mode 0644, single-linked, and owned by the private secrets directory owner",
			)
		case !sdbxsecrets.ContainerReadable(secret) &&
			info.Mode().Perm()&0o077 != 0:
			problems = append(problems, secret+" is accessible by group or other users")
		case info.Size() == 0 && !d.secretContentIsOptional(secret):
			problems = append(problems, secret+" is not configured")
		}
	}
	if d.Config != nil && d.Config.ActiveServices["gluetun"] {
		if problem := d.checkGluetunCredentials(); problem != "" {
			problems = append(problems, problem)
		}
	}
	if d.Config != nil && d.Config.ActiveServices["traefik"] {
		if err := sdbxsecrets.ValidateConsoleProxyPKI(secretsDir); err != nil {
			problems = append(problems, "console proxy PKI is invalid")
		}
	}
	if len(problems) > 0 {
		return false, strings.Join(problems, "; ")
	}
	return true, fmt.Sprintf("%d active credential file(s) configured", len(required))
}

func (d *Doctor) secretContentIsOptional(filename string) bool {
	if d.Graph == nil {
		return false
	}
	name := strings.TrimSuffix(filename, ".txt")
	for _, serviceName := range d.Graph.Order {
		resolved := d.Graph.Services[serviceName]
		if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
			continue
		}
		for _, secret := range resolved.FinalDefinition.Secrets {
			if secret.Name == name && secret.Optional {
				return true
			}
		}
	}
	return false
}

func containerReadableSecretIsProtected(dirInfo, fileInfo os.FileInfo) bool {
	if dirInfo == nil || fileInfo == nil ||
		fileInfo.Mode().Perm() != 0o644 {
		return false
	}
	dirStat, dirOK := dirInfo.Sys().(*syscall.Stat_t)
	fileStat, fileOK := fileInfo.Sys().(*syscall.Stat_t)
	return dirOK && fileOK &&
		dirStat.Uid == fileStat.Uid &&
		fileStat.Nlink == 1
}

func (d *Doctor) requiredSecretFiles() []string {
	if d.Graph == nil {
		return []string{
			"authelia_jwt_secret.txt",
			"authelia_session_secret.txt",
			"authelia_storage_encryption_key.txt",
		}
	}
	required := make(map[string]struct{})
	for _, serviceName := range d.Graph.Order {
		resolved := d.Graph.Services[serviceName]
		if resolved == nil || !resolved.Enabled || resolved.FinalDefinition == nil {
			continue
		}
		for _, secret := range resolved.FinalDefinition.Secrets {
			required[secret.Name+".txt"] = struct{}{}
		}
	}
	for serviceName, filename := range map[string]string{
		"qbittorrent": "qbittorrent_password.txt",
		"filebrowser": "filebrowser_admin_password.txt",
		"sonarr":      "sonarr_admin_password.txt",
		"prowlarr":    "prowlarr_admin_password.txt",
	} {
		if d.Config != nil && d.Config.ActiveServices[serviceName] {
			required[filename] = struct{}{}
		}
	}
	if d.Config != nil && d.Config.ActiveServices["traefik"] {
		for _, filename := range []string{
			sdbxsecrets.ConsoleProxyCAFile,
			sdbxsecrets.ConsoleProxyServerCertFile,
			sdbxsecrets.ConsoleProxyServerKeyFile,
			sdbxsecrets.ConsoleProxyClientCertFile,
			sdbxsecrets.ConsoleProxyClientKeyFile,
		} {
			required[filename] = struct{}{}
		}
	}
	result := make([]string, 0, len(required))
	for filename := range required {
		result = append(result, filename)
	}
	sort.Strings(result)
	return result
}

func (d *Doctor) checkGluetunCredentials() string {
	configRoot := d.resolveProjectPath(d.Config.ConfigPath)
	path := filepath.Join(configRoot, "gluetun", "gluetun.env")
	info, err := os.Lstat(path)
	if err != nil {
		return "Gluetun provider config is missing"
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "Gluetun provider config is not a regular file"
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "Gluetun provider config is accessible by group or other users"
	}
	data, err := securefs.ReadRegularFile(path, maxDoctorConfigSize)
	if err != nil {
		return "Gluetun provider config could not be read"
	}
	credentialKeys := map[string]bool{
		"OPENVPN_USER":          true,
		"OPENVPN_PASSWORD":      true,
		"WIREGUARD_PRIVATE_KEY": true,
	}
	configured := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || !credentialKeys[strings.TrimSpace(key)] {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" || strings.Contains(strings.ToLower(value), "your_") {
			return "Gluetun provider credentials still contain generated placeholders"
		}
		configured = true
	}
	if !configured {
		return "Gluetun provider credentials are not configured"
	}
	return ""
}

// configuredSecretsPath returns Config.SecretsPath or the default "secrets".
func (d *Doctor) configuredSecretsPath() string {
	if d.Config != nil && d.Config.SecretsPath != "" {
		return d.Config.SecretsPath
	}
	cfg, err := config.Load()
	if err != nil || cfg.SecretsPath == "" {
		return "secrets"
	}
	return cfg.SecretsPath
}

// resolveProjectPath returns rel as-is if absolute; otherwise joins it with
// the project directory.
func (d *Doctor) resolveProjectPath(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(d.ProjectDir, rel)
}

// checkConfiguredPaths verifies ConfigPath, DataPath, and SecretsPath exist
// and are writable. Catches typos in .sdbx.yaml at preflight rather than at
// docker bind-mount time.
func (d *Doctor) checkConfiguredPaths(_ context.Context) (bool, string) {
	cfg := d.Config
	if cfg == nil {
		var err error
		cfg, err = config.Load()
		if err != nil {
			return false, fmt.Sprintf("config load failed: %v", err)
		}
	}

	type pathSpec struct {
		label string
		raw   string
	}
	specs := []pathSpec{
		{"config_path", cfg.ConfigPath},
		{"data_path", cfg.DataPath},
		{"downloads_path", cfg.DownloadsPath},
		{"media_path", cfg.MediaPath},
		{"secrets_path", cfg.SecretsPath},
	}

	var problems []string
	for _, p := range specs {
		if p.raw == "" {
			problems = append(problems, fmt.Sprintf("%s empty", p.label))
			continue
		}
		resolved := d.resolveProjectPath(p.raw)
		info, err := os.Lstat(resolved)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s missing (%s)", p.label, resolved))
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			problems = append(problems, fmt.Sprintf("%s not a directory (%s)", p.label, resolved))
			continue
		}
		if err := unix.Access(resolved, unix.W_OK|unix.X_OK); err != nil {
			problems = append(problems, fmt.Sprintf("%s not writable (%s)", p.label, resolved))
			continue
		}
	}

	if len(problems) > 0 {
		return false, strings.Join(problems, "; ")
	}
	return true, "All paths writable"
}

// CheckVPN verifies the configured download path. When VPN protection is
// enabled, the public-IP probe runs inside Gluetun's network namespace. A
// host-side request would only prove that the host itself has Internet access.
func (d *Doctor) CheckVPN(ctx context.Context) (bool, string) {
	vpnEnabled := false
	if d.Config != nil {
		vpnEnabled = d.Config.ActiveServices["gluetun"]
	} else {
		configPath := filepath.Join(d.ProjectDir, ".sdbx.yaml")
		data, err := securefs.ReadRegularFile(configPath, maxProjectConfigSize)
		if err != nil {
			return false, fmt.Sprintf("Could not read project VPN configuration: %v", err)
		}
		var projectConfig struct {
			VPNEnabled bool `yaml:"vpn_enabled"`
		}
		if err := yaml.Unmarshal(data, &projectConfig); err != nil {
			return false, fmt.Sprintf("Could not parse project VPN configuration: %v", err)
		}
		vpnEnabled = projectConfig.VPNEnabled
	}
	if !vpnEnabled {
		return true, "VPN disabled by configuration; torrent traffic uses the host public IP"
	}
	if d.vpnEgress == nil {
		return false, "VPN egress probe is not configured"
	}
	output, err := d.vpnEgress(ctx)
	if err != nil {
		return false, fmt.Sprintf(
			"Gluetun egress check failed; the container may be stopped, unhealthy, or unable to reach the tunnel: %v",
			err,
		)
	}
	ip := strings.TrimSpace(output)
	if len(ip) > net.IPv6len*4 || net.ParseIP(ip) == nil {
		return false, "Gluetun egress check returned an invalid public IP"
	}

	return true, fmt.Sprintf("Gluetun tunnel egress is reachable (%s)", ip)
}

// checkArrAuth verifies that every enabled *arr's config.xml requires native
// Forms authentication from every address. Authelia protects public routes,
// while this application-owned layer prevents Docker-network peers from
// bypassing the route boundary.
func (d *Doctor) checkArrAuth(_ context.Context) (bool, string) {
	cfg := d.Config
	if cfg == nil {
		var err error
		cfg, err = config.Load()
		if err != nil {
			return false, fmt.Sprintf("config load failed: %v", err)
		}
	}

	root := cfg.ConfigPath
	if root == "" {
		root = "./configs"
	}
	root = d.resolveProjectPath(root)

	// Same config.xml-based set the registry recognises in lookup.go.
	// Bazarr is deliberately excluded: it uses config.yaml rather than the
	// Servarr config.xml contract. Hardcode this list to keep the package
	// import-cycle-free (doctor → integrate would loop).
	candidates := []string{"sonarr", "radarr", "lidarr", "whisparr", "prowlarr"}

	var problems []string
	for _, name := range candidates {
		if cfg.ActiveServices != nil && !cfg.ActiveServices[name] {
			continue
		}
		if cfg.ActiveServices == nil && !cfg.IsAddonEnabled(name) {
			continue
		}
		path := filepath.Join(root, name, "config.xml")
		data, err := securefs.ReadRegularFile(path, maxDoctorConfigSize)
		if err != nil {
			if os.IsNotExist(err) {
				// Not yet provisioned — sdbx generate will create it on
				// next run. Treat as fine for this check.
				continue
			}
			problems = append(problems, fmt.Sprintf("%s: read config.xml failed (%v)", name, err))
			continue
		}
		body := string(data)
		apiKey, hasAPIKey, duplicateAPIKey := doctorXMLField(body, "ApiKey")
		authMethod, hasAuthMethod, duplicateAuthMethod := doctorXMLField(
			body,
			"AuthenticationMethod",
		)
		authRequired, hasAuthRequired, duplicateAuthRequired := doctorXMLField(
			body,
			"AuthenticationRequired",
		)

		if !hasAPIKey || apiKey == "" {
			problems = append(problems, fmt.Sprintf("%s: <ApiKey> missing — run `sdbx generate`", name))
		}
		if duplicateAPIKey || duplicateAuthMethod || duplicateAuthRequired {
			problems = append(
				problems,
				fmt.Sprintf("%s: duplicate security fields make config.xml ambiguous — repair the file, then run `sdbx generate`", name),
			)
			continue
		}
		if !hasAuthMethod || !strings.EqualFold(authMethod, "forms") {
			problems = append(
				problems,
				fmt.Sprintf("%s: AuthenticationMethod must be Forms — run `sdbx generate`, then `sdbx integrate`", name),
			)
		}
		if !hasAuthRequired || !strings.EqualFold(authRequired, "enabled") {
			problems = append(
				problems,
				fmt.Sprintf("%s: AuthenticationRequired must be Enabled — run `sdbx generate`, then `sdbx integrate`", name),
			)
		}
	}

	if len(problems) > 0 {
		return false, strings.Join(problems, "; ")
	}
	return true, "All enabled *arrs require Forms authentication and have one API key"
}

func doctorXMLField(body, field string) (string, bool, bool) {
	open := "<" + field + ">"
	close := "</" + field + ">"
	if strings.Count(body, open) != 1 || strings.Count(body, close) != 1 {
		count := strings.Count(body, open)
		return "", count > 0, count > 1 || strings.Count(body, close) > 1
	}
	start := strings.Index(body, open) + len(open)
	endOffset := strings.Index(body[start:], close)
	if endOffset < 0 {
		return "", false, false
	}
	return strings.TrimSpace(body[start : start+endOffset]), true, false
}
