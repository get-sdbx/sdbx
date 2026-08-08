package imageaudit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/registry"
)

type fakeResolver struct {
	images map[string]registry.ResolvedImage
	err    error
}

func (r fakeResolver) Resolve(
	_ context.Context,
	repository, tag string,
) (registry.ResolvedImage, error) {
	if r.err != nil {
		return registry.ResolvedImage{}, r.err
	}
	image, ok := r.images[repository+":"+tag]
	if !ok {
		return registry.ResolvedImage{}, errors.New("missing fixture")
	}
	return image, nil
}

func TestBuildIsSortedCompleteAndImmutable(t *testing.T) {
	digest := func(value string) string {
		return "sha256:" + strings.Repeat(value, 64)
	}
	definitions := []*registry.ServiceDefinition{
		{
			Metadata: registry.ServiceMetadata{Name: "zeta"},
			Spec: registry.ServiceSpec{
				Image: registry.ImageSpec{Repository: "example/zeta", Tag: "1"},
			},
			Conditions: registry.Conditions{RequireAddon: true},
		},
		{
			Metadata: registry.ServiceMetadata{Name: "alpha"},
			Spec: registry.ServiceSpec{
				Image: registry.ImageSpec{Repository: "example/alpha", Tag: "2"},
			},
		},
	}
	resolver := fakeResolver{images: map[string]registry.ResolvedImage{
		"example/alpha:2": {
			Digest: digest("a"),
			PlatformDigests: map[string]string{
				"linux/amd64":    digest("b"),
				"linux/arm64/v8": digest("c"),
			},
		},
		"example/zeta:1": {
			Digest: digest("d"),
			PlatformDigests: map[string]string{
				"linux/amd64": digest("e"),
				"linux/arm64": digest("f"),
			},
		},
	}}

	inventory, err := Build(context.Background(), definitions, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.SchemaVersion != 1 || len(inventory.Images) != 2 {
		t.Fatalf("inventory = %#v", inventory)
	}
	if inventory.Images[0].Service != "alpha" ||
		inventory.Images[0].Kind != "core" ||
		inventory.Images[1].Service != "zeta" ||
		inventory.Images[1].Kind != "addon" {
		t.Fatalf("image order or kinds = %#v", inventory.Images)
	}
	if inventory.Images[0].Platforms[1].Platform != "linux/arm64" ||
		inventory.Images[0].Platforms[1].Digest != digest("c") {
		t.Fatalf("normalized arm64 platform = %#v", inventory.Images[0].Platforms)
	}
	if definitions[0].Metadata.Name != "zeta" {
		t.Fatal("Build mutated caller definition order")
	}
}

func TestBuildRejectsIncompleteOrDuplicateInventory(t *testing.T) {
	validDigest := "sha256:" + strings.Repeat("a", 64)
	definition := &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: "test"},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{Repository: "example/test", Tag: "1"},
		},
	}
	resolver := fakeResolver{images: map[string]registry.ResolvedImage{
		"example/test:1": {
			Digest: validDigest,
			PlatformDigests: map[string]string{
				"linux/amd64": validDigest,
			},
		},
	}}

	if _, err := Build(context.Background(), []*registry.ServiceDefinition{
		definition,
	}, resolver); err == nil || !strings.Contains(err.Error(), "linux/arm64") {
		t.Fatalf("missing arm64 error = %v", err)
	}
	if _, err := Build(context.Background(), []*registry.ServiceDefinition{
		definition,
		definition,
	}, fakeResolver{images: map[string]registry.ResolvedImage{
		"example/test:1": {
			Digest: validDigest,
			PlatformDigests: map[string]string{
				"linux/amd64": validDigest,
				"linux/arm64": validDigest,
			},
		},
	}}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v", err)
	}
}
