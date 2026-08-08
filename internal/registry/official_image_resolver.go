package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"sync"

	officialservices "github.com/get-sdbx/sdbx/services"
)

// OfficialImageDigestResolver binds official image references to the reviewed
// OCI snapshot embedded in the binary. References not present in the official
// catalog may be resolved by the explicit fallback.
type OfficialImageDigestResolver struct {
	fallback ImageDigestResolver
	once     sync.Once
	images   map[string]ResolvedImage
	loadErr  error
}

// NewOfficialImageDigestResolver creates a resolver for secure first-run and
// catalog-mutation defaults. The fallback exists only for explicit external
// source images that cannot be represented by the official snapshot.
func NewOfficialImageDigestResolver(
	fallback ImageDigestResolver,
) *OfficialImageDigestResolver {
	return &OfficialImageDigestResolver{fallback: fallback}
}

// Resolve returns the reviewed official pin when one exists. It never refreshes
// an official tag through the registry implicitly.
func (r *OfficialImageDigestResolver) Resolve(
	ctx context.Context,
	repository, tag string,
) (ResolvedImage, error) {
	reference, err := imageReference(repository, tag)
	if err != nil {
		return ResolvedImage{}, err
	}
	r.once.Do(func() {
		definitions, loadErr := NewEmbeddedSource().Load(context.Background())
		if loadErr != nil {
			r.loadErr = fmt.Errorf("load embedded definitions: %w", loadErr)
			return
		}
		r.images, r.loadErr = parseOfficialImageSnapshot(
			officialservices.ImageLock,
			definitions,
		)
	})
	if r.loadErr != nil {
		return ResolvedImage{}, r.loadErr
	}
	if resolved, ok := r.images[reference]; ok {
		return cloneResolvedImage(resolved), nil
	}
	if r.fallback == nil {
		return ResolvedImage{}, fmt.Errorf(
			"image %s is not present in the reviewed official snapshot",
			reference,
		)
	}
	resolved, err := r.fallback.Resolve(ctx, repository, tag)
	if err != nil {
		return ResolvedImage{}, err
	}
	return cloneResolvedImage(resolved), nil
}

func cloneResolvedImage(image ResolvedImage) ResolvedImage {
	return ResolvedImage{
		Digest:          image.Digest,
		PlatformDigests: cloneSortedMap(image.PlatformDigests),
	}
}

func parseOfficialImageSnapshot(
	data []byte,
	definitions []*ServiceDefinition,
) (map[string]ResolvedImage, error) {
	var snapshot struct {
		SchemaVersion int `json:"schemaVersion"`
		Images        []struct {
			Service     string `json:"service"`
			Kind        string `json:"kind"`
			Repository  string `json:"repository"`
			Tag         string `json:"tag"`
			IndexDigest string `json:"indexDigest"`
			Platforms   []struct {
				Platform string `json:"platform"`
				Digest   string `json:"digest"`
			} `json:"platforms"`
		} `json:"images"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("decode official image snapshot: %w", err)
	}
	if snapshot.SchemaVersion != 1 {
		return nil, fmt.Errorf(
			"unsupported official image snapshot schema %d",
			snapshot.SchemaVersion,
		)
	}

	expected := make(map[string]*ServiceDefinition, len(definitions))
	for _, definition := range definitions {
		if definition == nil {
			return nil, fmt.Errorf("embedded catalog contains a nil definition")
		}
		name := definition.Metadata.Name
		if _, exists := expected[name]; exists {
			return nil, fmt.Errorf("embedded catalog contains duplicate service %q", name)
		}
		expected[name] = definition
	}
	if len(snapshot.Images) != len(expected) {
		return nil, fmt.Errorf(
			"official image snapshot has %d services; embedded catalog has %d",
			len(snapshot.Images),
			len(expected),
		)
	}

	images := make(map[string]ResolvedImage, len(snapshot.Images))
	seenServices := make(map[string]struct{}, len(snapshot.Images))
	for _, image := range snapshot.Images {
		definition, ok := expected[image.Service]
		if !ok {
			return nil, fmt.Errorf(
				"official image snapshot contains unknown service %q",
				image.Service,
			)
		}
		if _, exists := seenServices[image.Service]; exists {
			return nil, fmt.Errorf(
				"official image snapshot contains duplicate service %q",
				image.Service,
			)
		}
		seenServices[image.Service] = struct{}{}
		expectedKind := "core"
		if definition.Conditions.RequireAddon {
			expectedKind = "addon"
		}
		if image.Kind != expectedKind {
			return nil, fmt.Errorf(
				"official image snapshot kind for %s is %q; expected %q",
				image.Service,
				image.Kind,
				expectedKind,
			)
		}
		if image.Repository != definition.Spec.Image.Repository ||
			image.Tag != definition.Spec.Image.Tag {
			return nil, fmt.Errorf(
				"official image snapshot reference for %s does not match its definition",
				image.Service,
			)
		}
		if !isSHA256Digest(image.IndexDigest) {
			return nil, fmt.Errorf(
				"official image snapshot has invalid index digest for %s",
				image.Service,
			)
		}
		platforms := make(map[string]string, len(image.Platforms))
		for _, platform := range image.Platforms {
			if platform.Platform != "linux/amd64" &&
				platform.Platform != "linux/arm64" {
				return nil, fmt.Errorf(
					"official image snapshot has unsupported platform %q for %s",
					platform.Platform,
					image.Service,
				)
			}
			if !isSHA256Digest(platform.Digest) {
				return nil, fmt.Errorf(
					"official image snapshot has invalid %s digest for %s",
					platform.Platform,
					image.Service,
				)
			}
			if _, exists := platforms[platform.Platform]; exists {
				return nil, fmt.Errorf(
					"official image snapshot has duplicate platform %s for %s",
					platform.Platform,
					image.Service,
				)
			}
			platforms[platform.Platform] = platform.Digest
		}
		expectedPlatforms := []string{"linux/amd64", "linux/arm64"}
		actualPlatforms := make([]string, 0, len(platforms))
		for platform := range platforms {
			actualPlatforms = append(actualPlatforms, platform)
		}
		sort.Strings(actualPlatforms)
		if !reflect.DeepEqual(actualPlatforms, expectedPlatforms) {
			return nil, fmt.Errorf(
				"official image snapshot is incomplete for %s",
				image.Service,
			)
		}

		reference, err := imageReference(image.Repository, image.Tag)
		if err != nil {
			return nil, fmt.Errorf(
				"official image snapshot has invalid reference for %s: %w",
				image.Service,
				err,
			)
		}
		resolved := ResolvedImage{
			Digest:          image.IndexDigest,
			PlatformDigests: platforms,
		}
		if existing, exists := images[reference]; exists &&
			!reflect.DeepEqual(existing, resolved) {
			return nil, fmt.Errorf(
				"official image snapshot has conflicting reference %s",
				reference,
			)
		}
		images[reference] = resolved
	}
	return images, nil
}
