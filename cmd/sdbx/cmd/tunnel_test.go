package cmd

import (
	"strings"
	"testing"

	sdbxcloudflare "github.com/get-sdbx/sdbx/internal/cloudflare"
)

func TestTunnelHelpStatesRemoteOwnership(t *testing.T) {
	for _, expected := range []string{
		"remotely managed",
		"connector token cannot create or update",
	} {
		if !strings.Contains(tunnelCmd.Long, expected) {
			t.Fatalf("tunnel help missing %q:\n%s", expected, tunnelCmd.Long)
		}
	}
	if !strings.Contains(tunnelRoutesCmd.Long, sdbxcloudflare.OriginService) {
		t.Fatalf(
			"route help missing origin %q:\n%s",
			sdbxcloudflare.OriginService,
			tunnelRoutesCmd.Long,
		)
	}
}
