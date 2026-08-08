// Package presets defines SDBX's recommended addon stacks. Like Debian's
// tasksel, presets bundle a coherent set of addons under a memorable name
// so users can adopt a complete profile in one command rather than enabling
// 15 addons individually.
//
// Built-in presets are bundled into the binary via go:embed. User-defined
// presets in ~/.config/sdbx/presets.yaml override the built-ins by name.
package presets

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/get-sdbx/sdbx/internal/securefs"
	"gopkg.in/yaml.v3"
)

//go:embed builtin.yaml
var builtinYAML []byte

// Preset is one named stack of addons.
type Preset struct {
	Name        string   `json:"name" yaml:"name"`
	Title       string   `json:"title" yaml:"title"`
	Icon        string   `json:"icon" yaml:"icon"`
	Description string   `json:"description" yaml:"description"`
	Addons      []string `json:"addons" yaml:"addons"`
}

// Collection is a set of presets, optionally with apiVersion/kind metadata
// (mirroring the service definition schema).
type Collection struct {
	APIVersion string   `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string   `json:"kind,omitempty" yaml:"kind,omitempty"`
	Presets    []Preset `json:"presets" yaml:"presets"`
}

// Load returns the merged preset collection: built-in presets shipped with
// the binary, overridden by ~/.config/sdbx/presets.yaml entries (matched by
// name).
func Load() (*Collection, error) {
	builtin, err := LoadBuiltin()
	if err != nil {
		return nil, fmt.Errorf("load builtin presets: %w", err)
	}
	user, err := loadUser()
	if err != nil {
		return nil, fmt.Errorf("load user presets: %w", err)
	}
	return mergeCollections(builtin, user), nil
}

// LoadBuiltin returns only the presets compiled into the binary. It is used
// for deterministic release references and checks that must not inherit a
// maintainer's local preset overrides.
func LoadBuiltin() (*Collection, error) {
	var c Collection
	if err := yaml.Unmarshal(builtinYAML, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func loadUser() (*Collection, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		// No home dir resolvable — treat as empty (caller falls back to builtin).
		return &Collection{}, nil
	}
	path := filepath.Join(home, ".config", "sdbx", "presets.yaml")
	data, err := securefs.ReadRegularFile(path, 1<<20)
	if err != nil {
		if os.IsNotExist(err) {
			return &Collection{}, nil
		}
		return nil, err
	}
	var c Collection
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

func mergeCollections(builtin, user *Collection) *Collection {
	byName := make(map[string]Preset, len(builtin.Presets)+len(user.Presets))
	for _, p := range builtin.Presets {
		byName[p.Name] = p
	}
	for _, p := range user.Presets {
		byName[p.Name] = p // user overrides builtin
	}
	out := &Collection{APIVersion: builtin.APIVersion, Kind: builtin.Kind}
	for _, p := range byName {
		out.Presets = append(out.Presets, p)
	}
	sort.Slice(out.Presets, func(i, j int) bool {
		return out.Presets[i].Name < out.Presets[j].Name
	})
	return out
}

// Find returns the preset with the given name, or nil if not found.
func (c *Collection) Find(name string) *Preset {
	for i := range c.Presets {
		if c.Presets[i].Name == name {
			return &c.Presets[i]
		}
	}
	return nil
}
