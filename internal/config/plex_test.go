package config

import (
	"path/filepath"
	"testing"
)

func TestPlexHostAccessValidation(t *testing.T) {
	for _, device := range []string{"", "/dev/dri/renderD128", "/dev/dri/renderD129"} {
		if err := (PlexConfig{HardwareDevice: device}).Validate(); err != nil {
			t.Fatalf("valid device %q: %v", device, err)
		}
	}
	for _, device := range []string{"/dev/mem", "/dev/dri", "/dev/dri/../mem", "/dev/dri/renderD128:/dev/null", "/dev/dri/renderD128\n", "relative", "/dev/dri/renderD128/file"} {
		if err := (PlexConfig{HardwareDevice: device}).Validate(); err == nil {
			t.Fatalf("accepted invalid device %q", device)
		}
	}
	for _, address := range []string{"10.0.0.10", "192.168.10.20", "172.16.0.10", "127.0.0.1", "::1", "fd00::10"} {
		if err := (PlexConfig{LANAddress: address}).Validate(); err != nil {
			t.Fatalf("valid private address %q: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0", "::", "192.0.2.10", "2001:db8::1", "localhost", "10.0.0.1:32400", "fe80::1%eth0", "::ffff:127.0.0.1", "10.0.0.1\n"} {
		if err := (PlexConfig{LANAddress: address}).Validate(); err == nil {
			t.Fatalf("accepted invalid/private-listener address %q", address)
		}
	}
	for _, port := range []int{-1, 65536} {
		if err := (PlexConfig{LANPort: port}).Validate(); err == nil {
			t.Fatalf("accepted port %d", port)
		}
	}
	if err := (PlexConfig{AMDVAAPI: true}).Validate(); err == nil {
		t.Fatal("AMD compatibility must require an explicit render device")
	}
	if got := (PlexConfig{LANAddress: "fd00::10"}).LANBinding(); got != "[fd00::10]:32400" {
		t.Fatalf("IPv6 binding = %q", got)
	}
	if got := (PlexConfig{LANPort: 32401}).LANBinding(); got != "" {
		t.Fatalf("port alone exposed a listener: %q", got)
	}
}

func TestPlexSettingsRoundTrip(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PlexEnabled = true
	cfg.Plex = PlexConfig{HardwareDevice: "/dev/dri/renderD128", AMDVAAPI: true, LANAddress: "10.0.0.10", LANPort: 32401}
	path := filepath.Join(t.TempDir(), ".sdbx.yaml")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Plex != cfg.Plex {
		t.Fatalf("Plex settings changed during round trip: %#v", loaded.Plex)
	}
}
