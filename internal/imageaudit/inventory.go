// Package imageaudit builds the immutable OCI inventory consumed by the
// maintainer vulnerability gate.
package imageaudit

import (
	"context"
	"fmt"
	"regexp"
	"sort"

	"github.com/get-sdbx/sdbx/internal/registry"
)

const SchemaVersion = 1

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Inventory is a deterministic snapshot of every official catalog image.
type Inventory struct {
	SchemaVersion int     `json:"schemaVersion"`
	Images        []Image `json:"images"`
}

// Image records the mutable authoring input and its immutable OCI result.
type Image struct {
	Service     string          `json:"service"`
	Kind        string          `json:"kind"`
	Repository  string          `json:"repository"`
	Tag         string          `json:"tag"`
	IndexDigest string          `json:"indexDigest"`
	Platforms   []PlatformImage `json:"platforms"`
}

// PlatformImage identifies the exact runtime manifest for one supported host
// architecture.
type PlatformImage struct {
	Platform string `json:"platform"`
	Digest   string `json:"digest"`
}

// Build resolves every definition and returns a stable Linux amd64/arm64
// inventory. It fails closed when a name is duplicated or either platform is
// unavailable.
func Build(
	ctx context.Context,
	definitions []*registry.ServiceDefinition,
	resolver registry.ImageDigestResolver,
) (*Inventory, error) {
	if resolver == nil {
		return nil, fmt.Errorf("image resolver is required")
	}

	sorted := append([]*registry.ServiceDefinition(nil), definitions...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i] == nil {
			return false
		}
		if sorted[j] == nil {
			return true
		}
		return sorted[i].Metadata.Name < sorted[j].Metadata.Name
	})

	inventory := &Inventory{
		SchemaVersion: SchemaVersion,
		Images:        make([]Image, 0, len(sorted)),
	}
	seen := make(map[string]struct{}, len(sorted))
	for _, definition := range sorted {
		if definition == nil {
			return nil, fmt.Errorf("catalog contains a nil service definition")
		}
		name := definition.Metadata.Name
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("catalog contains duplicate service %q", name)
		}
		seen[name] = struct{}{}

		resolved, err := resolver.Resolve(
			ctx,
			definition.Spec.Image.Repository,
			definition.Spec.Image.Tag,
		)
		if err != nil {
			return nil, fmt.Errorf("resolve %s image: %w", name, err)
		}
		if !digestPattern.MatchString(resolved.Digest) {
			return nil, fmt.Errorf("%s has invalid OCI index digest", name)
		}

		amd64 := resolved.PlatformDigests["linux/amd64"]
		arm64 := resolved.PlatformDigests["linux/arm64"]
		if arm64 == "" {
			arm64 = resolved.PlatformDigests["linux/arm64/v8"]
		}
		if !digestPattern.MatchString(amd64) {
			return nil, fmt.Errorf("%s has no valid linux/amd64 manifest", name)
		}
		if !digestPattern.MatchString(arm64) {
			return nil, fmt.Errorf("%s has no valid linux/arm64 manifest", name)
		}

		kind := "core"
		if definition.Conditions.RequireAddon {
			kind = "addon"
		}
		inventory.Images = append(inventory.Images, Image{
			Service:     name,
			Kind:        kind,
			Repository:  definition.Spec.Image.Repository,
			Tag:         definition.Spec.Image.Tag,
			IndexDigest: resolved.Digest,
			Platforms: []PlatformImage{
				{Platform: "linux/amd64", Digest: amd64},
				{Platform: "linux/arm64", Digest: arm64},
			},
		})
	}

	return inventory, nil
}
