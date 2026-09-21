package registry

import (
	"context"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
)

func TestPlexLockBindsOptionalHostAccess(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PlexEnabled = true
	base, err := calculateLockConfigDigest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, plex := range []config.PlexConfig{
		{HardwareDevice: "/dev/dri/renderD128"},
		{HardwareDevice: "/dev/dri/renderD129"},
		{HardwareDevice: "/dev/dri/renderD128", AMDVAAPI: true},
		{LANAddress: "10.0.0.10"},
		{LANAddress: "10.0.0.10", LANPort: 32401},
	} {
		cfg.Plex = plex
		digest, err := calculateLockConfigDigest(cfg)
		if err != nil || digest == base {
			t.Fatalf("host access did not change lock digest: %#v, %v", plex, err)
		}
	}
	cfg.Plex = config.PlexConfig{LANAddress: "10.0.0.10"}
	implicit, _ := calculateLockConfigDigest(cfg)
	cfg.Plex.LANPort = 32400
	explicit, _ := calculateLockConfigDigest(cfg)
	if implicit != explicit {
		t.Fatal("default port representations must have the same runtime digest")
	}
	cfg.Plex = config.PlexConfig{LANPort: 32401}
	inactive, _ := calculateLockConfigDigest(cfg)
	if inactive != base {
		t.Fatal("a port without a listen address changed runtime intent")
	}
}

func TestEmbeddedPlexHostPermissionsAreDeclared(t *testing.T) {
	def, err := NewEmbeddedSource().LoadService(context.Background(), "plex")
	if err != nil {
		t.Fatal(err)
	}
	required := RequiredCatalogPermissions(def)
	for _, want := range []string{PermissionDevice, PermissionHostPort} {
		found := false
		for _, permission := range required {
			found = found || permission == want
		}
		if !found {
			t.Fatalf("Plex host access lacks derived permission %s", want)
		}
	}
	if errs := NewValidator().Validate(def); HasErrors(errs) {
		t.Fatalf("invalid embedded Plex: %v", errs)
	}
	def.Spec.Container.ConditionalDevices[0].When = "{{ true }}"
	if errs := NewValidator().Validate(def); !HasErrors(errs) {
		t.Fatal("accepted a conditional device outside the supported activation contract")
	}
}
