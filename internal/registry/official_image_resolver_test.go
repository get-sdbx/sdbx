package registry

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	officialservices "github.com/get-sdbx/sdbx/services"
)

type fallbackImageResolver struct {
	called bool
	image  ResolvedImage
	err    error
}

func (r *fallbackImageResolver) Resolve(
	_ context.Context,
	_, _ string,
) (ResolvedImage, error) {
	r.called = true
	return r.image, r.err
}

func TestOfficialImageDigestResolverCoversEmbeddedCatalog(t *testing.T) {
	t.Parallel()
	definitions, err := NewEmbeddedSource().Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fallback := &fallbackImageResolver{err: errors.New("unexpected fallback")}
	resolver := NewOfficialImageDigestResolver(fallback)
	for _, definition := range definitions {
		resolved, err := resolver.Resolve(
			context.Background(),
			definition.Spec.Image.Repository,
			definition.Spec.Image.Tag,
		)
		if err != nil {
			t.Fatalf("%s: %v", definition.Metadata.Name, err)
		}
		if !isSHA256Digest(resolved.Digest) ||
			!isSHA256Digest(resolved.PlatformDigests["linux/amd64"]) ||
			!isSHA256Digest(resolved.PlatformDigests["linux/arm64"]) {
			t.Fatalf(
				"%s has incomplete official image pin: %#v",
				definition.Metadata.Name,
				resolved,
			)
		}
	}
	if fallback.called {
		t.Fatal("official catalog resolution used the network fallback")
	}
}

func TestOfficialImageDigestResolverUsesFallbackOnlyForExternalImage(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("a", 64)
	fallback := &fallbackImageResolver{image: ResolvedImage{
		Digest: digest,
		PlatformDigests: map[string]string{
			"linux/amd64": digest,
			"linux/arm64": digest,
		},
	}}
	resolver := NewOfficialImageDigestResolver(fallback)
	resolved, err := resolver.Resolve(
		context.Background(),
		"example/external",
		"1.0.0",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !fallback.called || resolved.Digest != digest {
		t.Fatalf("fallback result = %#v, called = %v", resolved, fallback.called)
	}
}

func TestParseOfficialImageSnapshotRejectsDrift(t *testing.T) {
	t.Parallel()
	definitions, err := NewEmbeddedSource().Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseOfficialImageSnapshot(
		[]byte(`{"schemaVersion":1,"images":[]}`),
		definitions,
	); err == nil || !strings.Contains(err.Error(), "services") {
		t.Fatalf("truncated snapshot error = %v", err)
	}
}

func TestParseOfficialImageSnapshotRejectsKindDrift(t *testing.T) {
	t.Parallel()
	definitions, err := NewEmbeddedSource().Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(
		officialservices.ImageLock,
		[]byte(`"kind": "addon"`),
		[]byte(`"kind": "core"`),
		1,
	)
	if _, err := parseOfficialImageSnapshot(
		tampered,
		definitions,
	); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("kind drift error = %v", err)
	}
}
