// Package addons coordinates addon state changes and project regeneration.
package addons

import (
	"context"
	"fmt"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/generator"
	"github.com/get-sdbx/sdbx/internal/registry"
)

type Manager struct {
	ProjectDir    string
	Config        *config.Config
	Registry      *registry.Registry
	Lock          *registry.LockFile
	CLIVersion    string
	ImageResolver registry.ImageDigestResolver
}

type Result struct {
	Name        string `json:"name"`
	Action      string `json:"action"`
	Changed     bool   `json:"changed"`
	Regenerated bool   `json:"regenerated"`
}

func (m *Manager) Enable(ctx context.Context, name string) (*Result, error) {
	return m.apply(ctx, name, "enable", func() bool {
		if m.Config.IsAddonEnabled(name) {
			return false
		}
		m.Config.EnableAddon(name)
		return true
	})
}

func (m *Manager) Disable(ctx context.Context, name string) (*Result, error) {
	return m.apply(ctx, name, "disable", func() bool {
		if !m.Config.IsAddonEnabled(name) {
			return false
		}
		m.Config.DisableAddon(name)
		return true
	})
}

// BulkResult records what BulkEnable did with each addon in the request.
type BulkResult struct {
	Name   string `json:"name"`
	Action string `json:"action"` // "enabled", "already-enabled", "missing-from-registry"
	Err    error  `json:"-"`
}

// BulkEnable enables every addon in `names`, regenerating runtime files once
// at the end (not per-addon). Addons that don't exist in the registry are
// skipped with a "missing-from-registry" result rather than aborting the
// whole batch — partial preset adoption is the user-friendly default. On
// any regenerate failure the entire change set is rolled back.
func (m *Manager) BulkEnable(ctx context.Context, names []string) ([]BulkResult, error) {
	if m.ProjectDir == "" || m.Config == nil || m.Registry == nil {
		return nil, fmt.Errorf("manager not initialised (need ProjectDir, Config, Registry)")
	}

	results := make([]BulkResult, 0, len(names))
	previousAddons := append([]string(nil), m.Config.Addons...)
	mutated := false

	for _, name := range names {
		def, _, err := m.Registry.GetService(ctx, name)
		if err != nil || def == nil || !def.Conditions.RequireAddon {
			results = append(results, BulkResult{Name: name, Action: "missing-from-registry"})
			continue
		}
		if m.Config.IsAddonEnabled(name) {
			results = append(results, BulkResult{Name: name, Action: "already-enabled"})
			continue
		}
		m.Config.EnableAddon(name)
		results = append(results, BulkResult{Name: name, Action: "enabled"})
		mutated = true
	}

	if !mutated {
		return results, nil
	}

	if err := m.regenerate(ctx); err != nil {
		m.Config.Addons = previousAddons
		return results, fmt.Errorf("regenerate failed (changes rolled back): %w", err)
	}
	return results, nil
}

func (m *Manager) apply(ctx context.Context, name, action string, mutate func() bool) (*Result, error) {
	if m.ProjectDir == "" {
		return nil, fmt.Errorf("project directory is required")
	}
	if m.Config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if m.Registry == nil {
		return nil, fmt.Errorf("registry is required")
	}

	def, _, err := m.Registry.GetService(ctx, name)
	if err != nil || !def.Conditions.RequireAddon {
		return nil, fmt.Errorf("addon not found: %s", name)
	}

	result := &Result{Name: name, Action: action}
	previousAddons := append([]string(nil), m.Config.Addons...)
	if !mutate() {
		return result, nil
	}

	result.Changed = true
	if err := m.regenerate(ctx); err != nil {
		m.Config.Addons = previousAddons
		return nil, fmt.Errorf("failed to regenerate project files: %w", err)
	}
	result.Regenerated = true
	return result, nil
}

func (m *Manager) regenerate(ctx context.Context) error {
	if m.Lock == nil {
		gen := generator.NewGeneratorWithRegistry(m.Config, m.ProjectDir, m.Registry)
		return gen.GenerateRuntimeFiles()
	}
	if m.CLIVersion == "" || m.ImageResolver == nil {
		return fmt.Errorf("locked project mutation requires CLI version and image resolver")
	}
	updated, err := generator.RegenerateRuntimeWithUpdatedLock(
		ctx,
		m.Config,
		m.ProjectDir,
		m.Registry,
		m.Lock,
		m.CLIVersion,
		m.ImageResolver,
	)
	if err != nil {
		return err
	}
	m.Lock = updated
	return nil
}
