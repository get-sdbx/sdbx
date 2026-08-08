// Package project provides verified access to an initialized SDBX project.
package project

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

// Verified is the immutable operational view derived from a project
// configuration and its schema-v2 lock.
type Verified struct {
	Dir      string
	Config   *config.Config
	Registry *registry.Registry
	Lock     *registry.LockFile
	Graph    *registry.ResolutionGraph
}

// LoadLock loads and structurally validates a project's lock file.
func LoadLock(projectDir string) (*registry.LockFile, error) {
	lockPath := filepath.Join(projectDir, ".sdbx.lock")
	lock, err := registry.NewLoader().LoadLockFile(lockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no .sdbx.lock found; run 'sdbx lock' to create one")
		}
		return nil, fmt.Errorf("failed to load .sdbx.lock: %w", err)
	}
	if err := registry.ValidateLockFile(lock, true); err != nil {
		return nil, fmt.Errorf("invalid .sdbx.lock: %w", err)
	}
	return lock, nil
}

// Verify rejects missing, malformed, or stale locks and resolves the active
// service graph without refreshing external sources or OCI metadata.
func Verify(
	ctx context.Context,
	projectDir string,
	cfg *config.Config,
	reg *registry.Registry,
	cliVersion string,
) (*Verified, error) {
	if projectDir == "" {
		return nil, fmt.Errorf("project directory is required")
	}
	if cfg == nil {
		return nil, fmt.Errorf("project configuration is required")
	}
	if reg == nil {
		return nil, fmt.Errorf("service registry is required")
	}
	if cliVersion == "" {
		return nil, fmt.Errorf("CLI version is required")
	}

	lock, err := LoadLock(projectDir)
	if err != nil {
		return nil, err
	}
	resolver, err := registry.NewLockedImageResolver(lock)
	if err != nil {
		return nil, fmt.Errorf("invalid .sdbx.lock: %w", err)
	}
	allowLocalSources := false
	for _, source := range lock.Sources {
		if source.Type == "local" {
			allowLocalSources = true
			break
		}
	}
	current, _, err := reg.GenerateLockFileWithOptions(
		ctx,
		cfg,
		registry.LockOptions{
			CLIVersion:        cliVersion,
			AllowLocalSources: allowLocalSources,
			ImageResolver:     resolver,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to verify .sdbx.lock: %w", err)
	}
	if diffs := reg.DiffLockFiles(lock, current); len(diffs) > 0 {
		return nil, fmt.Errorf(
			".sdbx.lock is stale: %s; run 'sdbx lock' after reviewing the change",
			diffs[0].Description,
		)
	}

	graph, err := reg.Resolve(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("resolve active service graph: %w", err)
	}
	if len(graph.Errors) > 0 {
		return nil, fmt.Errorf("active service graph is invalid: %w", graph.Errors[0])
	}
	cfg.ActiveServices = make(map[string]bool, len(graph.Order))
	for _, name := range graph.Order {
		resolved := graph.Services[name]
		if resolved != nil && resolved.Enabled && resolved.FinalDefinition != nil {
			cfg.ActiveServices[name] = true
		}
	}

	return &Verified{
		Dir:      projectDir,
		Config:   cfg,
		Registry: reg,
		Lock:     lock,
		Graph:    graph,
	}, nil
}

// VerifyGeneratedRuntime verifies both the locked service graph and every
// managed runtime file recorded in the lock. Use it before an operation reads,
// starts, exports, or mutates the generated project state.
func VerifyGeneratedRuntime(
	ctx context.Context,
	projectDir string,
	cfg *config.Config,
	reg *registry.Registry,
	cliVersion string,
) (*Verified, error) {
	verified, err := Verify(ctx, projectDir, cfg, reg, cliVersion)
	if err != nil {
		return nil, err
	}
	if err := registry.ValidateGeneratedFiles(
		projectDir,
		cfg.ConfigPath,
		verified.Lock,
	); err != nil {
		return nil, fmt.Errorf("generated project files: %w", err)
	}
	return verified, nil
}
