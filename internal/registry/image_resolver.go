package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	maxManifestBytes  = 4 << 20
	maxDockerErrBytes = 64 << 10
)

var (
	imageRepositoryPattern = regexp.MustCompile(
		`^[a-z0-9]+(?:(?:[._-]|__)[a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:(?:[._-]|__)[a-z0-9]+)*)*$`,
	)
	imageTagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

// DockerImageDigestResolver resolves image tags through the local Docker
// buildx client without pulling image layers.
type DockerImageDigestResolver struct {
	Timeout time.Duration
	mu      sync.Mutex
	cache   map[string]ResolvedImage
}

// NewDockerImageDigestResolver creates a resolver with bounded command time and
// an in-memory cache for duplicate image references.
func NewDockerImageDigestResolver() *DockerImageDigestResolver {
	return &DockerImageDigestResolver{
		Timeout: 30 * time.Second,
		cache:   make(map[string]ResolvedImage),
	}
}

// Resolve resolves repository:tag to its immutable index/manifest digest.
func (r *DockerImageDigestResolver) Resolve(
	ctx context.Context,
	repository, tag string,
) (ResolvedImage, error) {
	reference, err := imageReference(repository, tag)
	if err != nil {
		return ResolvedImage{}, err
	}

	r.mu.Lock()
	cached, ok := r.cache[reference]
	r.mu.Unlock()
	if ok {
		return cached, nil
	}

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout := newBoundedBuffer(maxManifestBytes)
	stderr := newBoundedBuffer(maxDockerErrBytes)
	// #nosec G204 -- the executable and subcommand are fixed, and
	// imageReference strictly validates the only variable argument.
	cmd := exec.CommandContext(
		commandContext,
		"docker",
		"buildx",
		"imagetools",
		"inspect",
		"--raw",
		reference,
	)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if commandContext.Err() != nil {
			return ResolvedImage{}, fmt.Errorf(
				"timed out resolving image %s after %s",
				reference,
				timeout,
			)
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = "docker buildx imagetools inspect failed"
		}
		return ResolvedImage{}, fmt.Errorf("cannot resolve image %s: %s: %w", reference, message, err)
	}
	if stdout.Overflowed() {
		return ResolvedImage{}, fmt.Errorf(
			"manifest for %s exceeds %d-byte safety limit",
			reference,
			maxManifestBytes,
		)
	}

	resolved, err := parseRawImageManifest(stdout.Bytes())
	if err != nil {
		return ResolvedImage{}, fmt.Errorf("invalid manifest for %s: %w", reference, err)
	}
	r.mu.Lock()
	r.cache[reference] = resolved
	r.mu.Unlock()
	return resolved, nil
}

func imageReference(repository, tag string) (string, error) {
	if !imageRepositoryPattern.MatchString(repository) {
		return "", fmt.Errorf("invalid image repository %q", repository)
	}
	if !imageTagPattern.MatchString(tag) {
		return "", fmt.Errorf("invalid image tag %q", tag)
	}
	return repository + ":" + tag, nil
}

func repositoryRegistry(repository string) string {
	first, _, hasPath := strings.Cut(repository, "/")
	if !hasPath ||
		(!strings.Contains(first, ".") &&
			!strings.Contains(first, ":") &&
			first != "localhost") {
		return "docker.io"
	}
	return first
}

func parseRawImageManifest(data []byte) (ResolvedImage, error) {
	if len(data) == 0 {
		return ResolvedImage{}, fmt.Errorf("empty manifest")
	}
	var index struct {
		SchemaVersion int `json:"schemaVersion"`
		Manifests     []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant,omitempty"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return ResolvedImage{}, err
	}
	if index.SchemaVersion != 2 {
		return ResolvedImage{}, fmt.Errorf("unsupported OCI schema version %d", index.SchemaVersion)
	}

	resolved := ResolvedImage{
		Digest: hashBytes(data),
	}
	for _, manifest := range index.Manifests {
		if manifest.Platform.OS == "" ||
			manifest.Platform.OS == "unknown" ||
			manifest.Platform.Architecture == "" ||
			manifest.Platform.Architecture == "unknown" {
			continue
		}
		if !isSHA256Digest(manifest.Digest) {
			return ResolvedImage{}, fmt.Errorf("invalid platform manifest digest")
		}
		platform := manifest.Platform.OS + "/" + manifest.Platform.Architecture
		if manifest.Platform.Variant != "" {
			platform += "/" + manifest.Platform.Variant
		}
		if resolved.PlatformDigests == nil {
			resolved.PlatformDigests = make(map[string]string)
		}
		if existing, exists := resolved.PlatformDigests[platform]; exists &&
			existing != manifest.Digest {
			return ResolvedImage{}, fmt.Errorf("multiple manifests for platform %s", platform)
		}
		resolved.PlatformDigests[platform] = manifest.Digest
	}
	return resolved, nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if b.buffer.Len()+len(data) > b.limit {
		remaining := b.limit - b.buffer.Len()
		if remaining > 0 {
			_, _ = b.buffer.Write(data[:remaining])
		}
		b.overflow = true
		return len(data), nil
	}
	return b.buffer.Write(data)
}

func (b *boundedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

func (b *boundedBuffer) String() string {
	return b.buffer.String()
}

func (b *boundedBuffer) Overflowed() bool {
	return b.overflow
}
