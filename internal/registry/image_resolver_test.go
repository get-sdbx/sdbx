package registry

import (
	"strings"
	"testing"
)

func TestParseRawImageManifestPinsIndexAndPlatforms(t *testing.T) {
	raw := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"os":"linux","architecture":"amd64"}},{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","platform":{"os":"linux","architecture":"arm64","variant":"v8"}},{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","platform":{"os":"unknown","architecture":"unknown"}}]}`)

	resolved, err := parseRawImageManifest(raw)
	if err != nil {
		t.Fatalf("parseRawImageManifest failed: %v", err)
	}
	if resolved.Digest != hashBytes(raw) {
		t.Fatalf("index digest = %q, want %q", resolved.Digest, hashBytes(raw))
	}
	if resolved.PlatformDigests["linux/amd64"] != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("amd64 digest = %q", resolved.PlatformDigests["linux/amd64"])
	}
	if resolved.PlatformDigests["linux/arm64/v8"] != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("arm64 digest = %q", resolved.PlatformDigests["linux/arm64/v8"])
	}
	if _, exists := resolved.PlatformDigests["unknown/unknown"]; exists {
		t.Fatal("attestation manifest was treated as a runtime platform")
	}
}

func TestImageReferenceRejectsInjectionAndMutableDigestSyntax(t *testing.T) {
	tests := []struct {
		repository string
		tag        string
	}{
		{repository: "alpine;touch /tmp/pwned", tag: "latest"},
		{repository: "alpine@sha256:" + strings.Repeat("a", 64), tag: "latest"},
		{repository: "alpine", tag: "latest --quiet"},
		{repository: "UPPERCASE/alpine", tag: "latest"},
	}
	for _, test := range tests {
		if _, err := imageReference(test.repository, test.tag); err == nil {
			t.Fatalf("imageReference accepted repository=%q tag=%q", test.repository, test.tag)
		}
	}

	if got, err := imageReference("ghcr.io/example/service", "v1.2.3"); err != nil ||
		got != "ghcr.io/example/service:v1.2.3" {
		t.Fatalf("imageReference = %q, %v", got, err)
	}
}

func TestRepositoryRegistry(t *testing.T) {
	tests := map[string]string{
		"alpine":                         "docker.io",
		"linuxserver/sonarr":             "docker.io",
		"docker.io/library/alpine":       "docker.io",
		"ghcr.io/hotio/whisparr":         "ghcr.io",
		"registry.example.test:5000/app": "registry.example.test:5000",
		"localhost/app":                  "localhost",
	}
	for repository, expected := range tests {
		if got := repositoryRegistry(repository); got != expected {
			t.Errorf("repositoryRegistry(%q) = %q, want %q", repository, got, expected)
		}
	}
}

func TestBoundedBufferCapsUntrustedCommandOutput(t *testing.T) {
	buffer := newBoundedBuffer(4)
	if _, err := buffer.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if !buffer.Overflowed() || buffer.String() != "abcd" {
		t.Fatalf("bounded buffer = %q overflow=%t", buffer.String(), buffer.Overflowed())
	}
}
