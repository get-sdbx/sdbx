package registry

import (
	"context"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
)

func TestLockBindsEffectiveCloudflareTunnelProtocol(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Expose.Mode = config.ExposeModeCloudflared
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	generate := func() *LockFile {
		t.Helper()
		lock, _, err := reg.GenerateLockFileWithOptions(context.Background(), cfg, LockOptions{
			CLIVersion: "test", TargetPlatform: "linux/amd64", ImageResolver: fakeImageResolver{},
		})
		if err != nil {
			t.Fatal(err)
		}
		return lock
	}
	http2 := generate()
	cfg.Expose.TunnelProtocol = ""
	omitted := generate()
	if diffs := reg.DiffLockFiles(http2, omitted); len(diffs) != 0 {
		t.Fatalf("omitted protocol differs from HTTP/2: %v", diffs)
	}
	for _, protocol := range []string{"quic", "auto"} {
		cfg.Expose.TunnelProtocol = protocol
		changed := generate()
		if changed.Metadata.ConfigDigest == http2.Metadata.ConfigDigest || len(reg.DiffLockFiles(http2, changed)) == 0 {
			t.Fatalf("changing protocol to %s did not invalidate the previous lock", protocol)
		}
		if changed.Services["cloudflared"].Image.PlatformDigest != http2.Services["cloudflared"].Image.PlatformDigest {
			t.Fatal("protocol choice changed image pin")
		}
	}
}
