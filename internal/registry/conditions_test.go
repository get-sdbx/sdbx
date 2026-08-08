package registry

import (
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
)

func TestMatchesActivationConditionsUsesOneFailClosedContract(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = true
	cfg.PlexEnabled = true
	cfg.JellyfinEnabled = false
	cfg.Expose.Mode = config.ExposeModeCloudflared

	testCases := []struct {
		name       string
		conditions Conditions
		cfg        *config.Config
		want       bool
	}{
		{
			name:       "nil-config",
			conditions: Conditions{Always: true},
		},
		{
			name: "missing-selector",
			cfg:  cfg,
		},
		{
			name: "ambiguous-selector",
			conditions: Conditions{
				Always:       true,
				RequireAddon: true,
			},
			cfg: cfg,
		},
		{
			name:       "always",
			conditions: Conditions{Always: true},
			cfg:        cfg,
			want:       true,
		},
		{
			name:       "addon",
			conditions: Conditions{RequireAddon: true},
			cfg:        cfg,
			want:       true,
		},
		{
			name:       "vpn",
			conditions: Conditions{RequireConfig: "vpn_enabled"},
			cfg:        cfg,
			want:       true,
		},
		{
			name:       "tunnel",
			conditions: Conditions{RequireConfig: "cloudflared"},
			cfg:        cfg,
			want:       true,
		},
		{
			name:       "plex",
			conditions: Conditions{RequireConfig: "plex_enabled"},
			cfg:        cfg,
			want:       true,
		},
		{
			name:       "jellyfin-disabled",
			conditions: Conditions{RequireConfig: "jellyfin_enabled"},
			cfg:        cfg,
		},
		{
			name:       "unknown",
			conditions: Conditions{RequireConfig: "unknown"},
			cfg:        cfg,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := MatchesActivationConditions(
				testCase.conditions,
				testCase.cfg,
			); got != testCase.want {
				t.Fatalf("MatchesActivationConditions() = %t, want %t", got, testCase.want)
			}
		})
	}
}

func TestEvaluateDependencyConditionCoversDocumentedResolverInputs(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.VPNEnabled = true
	cfg.Expose.Mode = config.ExposeModeDirect

	testCases := map[string]bool{
		conditionVPNEnabled:      true,
		conditionVPNDisabled:     false,
		conditionExposeLAN:       false,
		conditionExposeNotLAN:    true,
		conditionExposeDirect:    true,
		conditionExposeNotDirect: false,
		conditionExposeTunnel:    false,
		conditionExposeNotTunnel: true,
		conditionExposeHostPorts: true,
		conditionRoutingPath:     false,
		"{{ .Config.Unknown }}":  false,
	}
	for condition, want := range testCases {
		t.Run(condition, func(t *testing.T) {
			if got := evaluateDependencyCondition(condition, cfg); got != want {
				t.Fatalf("evaluateDependencyCondition() = %t, want %t", got, want)
			}
		})
	}
	if evaluateDependencyCondition(conditionVPNEnabled, nil) {
		t.Fatal("nil configuration evaluated true")
	}
}
