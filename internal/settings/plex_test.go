package settings

import (
	"context"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestPlexSettingsAreTransactionalAndPreservePins(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.PlexEnabled = true
	cfg.Expose.Mode = config.ExposeModeCloudflared
	m := testManager(t, dir, cfg)
	image := m.Lock.Services["plex"].Image
	inputs := [][2]string{{"plex.hardware_device", "/dev/dri/renderD128"}, {"plex.lan_port", "32401"}, {"plex.lan_address", "10.0.0.10"}}
	if runtime.GOARCH == "amd64" {
		inputs = append(inputs, [2]string{"plex.amd_vaapi", "true"})
	}
	for _, input := range inputs {
		if _, err := m.Set(context.Background(), input[0], input[1]); err != nil {
			t.Fatalf("set %s: %v", input[0], err)
		}
		if err := registry.ValidateGeneratedFiles(dir, cfg.ConfigPath, m.Lock); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(image, m.Lock.Services["plex"].Image) {
			t.Fatal("Plex setting changed its image pin")
		}
	}
	loaded, err := config.LoadFile(filepath.Join(dir, ".sdbx.yaml"))
	if err != nil || loaded.Plex != cfg.Plex {
		t.Fatalf("settings were not persisted: %v", err)
	}
	beforeConfig := readFile(t, filepath.Join(dir, ".sdbx.yaml"))
	beforeCompose := readFile(t, filepath.Join(dir, "compose.yaml"))
	beforeLock := readFile(t, filepath.Join(dir, ".sdbx.lock"))
	beforePlex := cfg.Plex
	invalidInputs := [][2]string{{"plex.hardware_device", "/dev/mem"}, {"plex.lan_address", "0.0.0.0"}, {"plex.lan_address", "192.0.2.1"}, {"plex.lan_port", "65536"}, {"plex.lan_port", "bad"}, {"plex.amd_vaapi", "bad"}}
	if runtime.GOARCH == "amd64" {
		invalidInputs = append(invalidInputs, [2]string{"plex.hardware_device", ""})
	} else {
		invalidInputs = append(invalidInputs, [2]string{"plex.amd_vaapi", "true"})
	}
	for _, invalid := range invalidInputs {
		if _, err := m.Set(context.Background(), invalid[0], invalid[1]); err == nil {
			t.Fatalf("invalid setting accepted: %v", invalid)
		}
		if cfg.Plex != beforePlex || readFile(t, filepath.Join(dir, ".sdbx.yaml")) != beforeConfig || readFile(t, filepath.Join(dir, "compose.yaml")) != beforeCompose || readFile(t, filepath.Join(dir, ".sdbx.lock")) != beforeLock {
			t.Fatal("invalid Plex setting changed live intent or runtime files")
		}
	}
	for _, input := range [][2]string{{"plex.amd_vaapi", "false"}, {"plex.hardware_device", ""}, {"plex.lan_address", ""}} {
		if _, err := m.Set(context.Background(), input[0], input[1]); err != nil {
			t.Fatal(err)
		}
	}
	compose := readFile(t, filepath.Join(dir, "compose.yaml"))
	for _, removed := range []string{"DOCKER_MODS=", "ATTACHED_DEVICES_PERMS=", "10.0.0.10:32401:32400"} {
		if strings.Contains(compose, removed) {
			t.Fatalf("disabled Plex capability remains in Compose: %s", removed)
		}
	}
}
