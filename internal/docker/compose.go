// Package docker provides Docker Compose operations for sdbx.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/get-sdbx/sdbx/internal/redact"
)

const (
	stateRunning                 = "running"
	healthHealthy                = "healthy"
	maxComposeCommandOutputBytes = 4 << 20
)

var ErrComposeOutputLimit = errors.New("docker compose output exceeded the byte limit")

// Service represents a Docker Compose service
type Service struct {
	Name     string `json:"container_name"`
	Service  string `json:"service"`
	Status   string `json:"status"`
	Health   string `json:"health,omitempty"`
	Ports    string `json:"ports,omitempty"`
	Image    string `json:"image"`
	Running  bool   `json:"running"`
	ExitCode int    `json:"exit_code,omitempty"`
}

// Compose handles Docker Compose operations
type Compose struct {
	ProjectDir  string
	ComposeFile string
	ProjectName string

	commandFactory func(context.Context, []string) *exec.Cmd
}

// NewCompose creates a new Compose instance
func NewCompose(projectDir string) *Compose {
	return &Compose{
		ProjectDir:  projectDir,
		ComposeFile: "compose.yaml",
		ProjectName: "sdbx",
	}
}

// run executes a docker compose command
func (c *Compose) run(ctx context.Context, args ...string) (string, error) {
	return c.runWithLimit(ctx, maxComposeCommandOutputBytes, args...)
}

func (c *Compose) runWithLimit(
	ctx context.Context,
	limit int,
	args ...string,
) (string, error) {
	cmdArgs := []string{"compose", "-f", c.ComposeFile, "-p", c.ProjectName}
	cmdArgs = append(cmdArgs, args...)

	commandContext, cancel := context.WithCancel(ctx)
	defer cancel()

	var cmd *exec.Cmd
	if c.commandFactory != nil {
		cmd = c.commandFactory(commandContext, cmdArgs)
	} else {
		// #nosec G204 -- the executable is fixed, arguments remain distinct
		// from a shell, and callers build only bounded Compose operations.
		cmd = exec.CommandContext(commandContext, "docker", cmdArgs...)
	}
	cmd.Dir = c.ProjectDir
	cmd.WaitDelay = 2 * time.Second

	stdout := newBoundedCommandBuffer(limit, cancel)
	stderr := newBoundedCommandBuffer(limit, cancel)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()
	if stdout.Exceeded() || stderr.Exceeded() {
		return "", ErrComposeOutputLimit
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if runErr != nil {
		return "", fmt.Errorf("%w: %s", runErr, redact.Text(stderr.String()))
	}

	return stdout.String(), nil
}

type boundedCommandBuffer struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func newBoundedCommandBuffer(limit int, cancel context.CancelFunc) *boundedCommandBuffer {
	return &boundedCommandBuffer{
		limit:  limit,
		cancel: cancel,
	}
}

func (w *boundedCommandBuffer) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	remaining := w.limit - w.buffer.Len()
	if remaining > 0 {
		writeLength := len(data)
		if writeLength > remaining {
			writeLength = remaining
		}
		_, _ = w.buffer.Write(data[:writeLength])
	}
	if len(data) > remaining && !w.exceeded {
		w.exceeded = true
		w.cancel()
	}
	return len(data), nil
}

func (w *boundedCommandBuffer) Exceeded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exceeded
}

func (w *boundedCommandBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func (w *boundedCommandBuffer) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.Len()
}

// Up starts all services
func (c *Compose) Up(ctx context.Context) error {
	_, err := c.run(ctx, "up", "-d", "--remove-orphans")
	return err
}

// Down stops all services
func (c *Compose) Down(ctx context.Context) error {
	_, err := c.run(ctx, "down")
	return err
}

// Restart restarts a specific service or all services
func (c *Compose) Restart(ctx context.Context, service string) error {
	if service == "" {
		_, err := c.run(ctx, "restart")
		return err
	}
	_, err := c.run(ctx, "restart", service)
	return err
}

// Pull pulls images for all services
func (c *Compose) Pull(ctx context.Context) error {
	_, err := c.run(ctx, "pull")
	return err
}

// Logs returns logs for a service
func (c *Compose) Logs(ctx context.Context, service string, lines int, follow bool) (string, error) {
	return c.logsWithLimit(ctx, service, lines, follow, maxComposeCommandOutputBytes)
}

// LogsBounded reads retained logs without ever buffering more than byteLimit
// bytes from either subprocess stream.
func (c *Compose) LogsBounded(
	ctx context.Context,
	service string,
	lines int,
	follow bool,
	byteLimit int,
) (string, error) {
	if byteLimit <= 0 || byteLimit > maxComposeCommandOutputBytes {
		return "", fmt.Errorf(
			"log byte limit must be between 1 and %d",
			maxComposeCommandOutputBytes,
		)
	}
	return c.logsWithLimit(ctx, service, lines, follow, byteLimit)
}

func (c *Compose) logsWithLimit(
	ctx context.Context,
	service string,
	lines int,
	follow bool,
	byteLimit int,
) (string, error) {
	args := []string{"logs"}
	if lines > 0 {
		args = append(args, "--tail", fmt.Sprintf("%d", lines))
	}
	if follow {
		args = append(args, "-f")
	}
	if service != "" {
		args = append(args, service)
	}
	return c.runWithLimit(ctx, byteLimit, args...)
}

// PS returns the status of all services
func (c *Compose) PS(ctx context.Context) ([]Service, error) {
	output, err := c.run(ctx, "ps", "--all", "--format", "json")
	if err != nil {
		return nil, err
	}

	var services []Service
	// docker compose ps --format json outputs one JSON object per line
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var svc struct {
			Name     string `json:"Name"`
			Service  string `json:"Service"`
			State    string `json:"State"`
			Health   string `json:"Health"`
			Image    string `json:"Image"`
			Ports    string `json:"Ports"`
			ExitCode int    `json:"ExitCode"`
		}
		if err := json.Unmarshal([]byte(line), &svc); err != nil {
			continue
		}
		services = append(services, Service{
			Name:     svc.Name,
			Service:  svc.Service,
			Status:   svc.State,
			Health:   svc.Health,
			Image:    svc.Image,
			Ports:    svc.Ports,
			Running:  svc.State == stateRunning,
			ExitCode: svc.ExitCode,
		})
	}

	return services, nil
}

// Exec executes a command in a running container
func (c *Compose) Exec(ctx context.Context, service string, cmd ...string) (string, error) {
	args := []string{"exec", "-T", service}
	args = append(args, cmd...)
	return c.run(ctx, args...)
}

// IsHealthy checks if a service is healthy
func (c *Compose) IsHealthy(ctx context.Context, service string) (bool, error) {
	services, err := c.PS(ctx)
	if err != nil {
		return false, err
	}

	for _, svc := range services {
		if svc.Service == service {
			return svc.Running && (svc.Health == "" || svc.Health == healthHealthy), nil
		}
	}

	return false, fmt.Errorf("service %s not found", service)
}

// WaitHealthy waits for a service to become healthy
func (c *Compose) WaitHealthy(ctx context.Context, service string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		healthy, err := c.IsHealthy(ctx, service)
		if err == nil && healthy {
			return nil
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("timeout waiting for %s to become healthy", service)
}
