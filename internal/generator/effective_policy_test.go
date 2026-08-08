package generator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

func TestComposeGeneratorRejectsRenderedHostPathTraversal(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	def := catalogPolicyTestDefinition()
	def.Permissions = []string{
		registry.PermissionConfigPath,
		"network:" + registry.NetworkApplication,
	}
	def.Spec.Volumes = []registry.VolumeMount{{
		HostPath:      "{{ .Config.ConfigPath }}/../../etc",
		ContainerPath: "/config",
	}}

	_, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err == nil || !strings.Contains(err.Error(), registry.PermissionHostMount) {
		t.Fatalf("generateService() error = %v, want effective host-mount rejection", err)
	}
}

func TestComposeGeneratorRejectsRenderedDockerSocket(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	def := catalogPolicyTestDefinition()
	def.Spec.Volumes = []registry.VolumeMount{{
		HostPath:      `{{ print "/var/run/" "docker.sock" }}`,
		ContainerPath: "/socket",
		ReadOnly:      true,
	}}

	_, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("generateService() error = %v, want effective Docker socket rejection", err)
	}
}

func TestComposeGeneratorRejectsRenderedHostNetwork(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	def := catalogPolicyTestDefinition()
	def.Spec.Networking.ModeTemplate = `{{ print "ho" "st" }}`

	_, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err == nil || !strings.Contains(err.Error(), registry.PermissionHostNetwork) {
		t.Fatalf("generateService() error = %v, want effective host-network rejection", err)
	}
}

func TestComposeGeneratorRejectsUndeclaredEffectiveEnvFilePath(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	def := catalogPolicyTestDefinition()
	def.Spec.Environment.EnvFile = []string{
		"{{ .Config.ConfigPath }}/service/runtime.env",
	}

	_, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err == nil || !strings.Contains(err.Error(), registry.PermissionConfigPath) {
		t.Fatalf("generateService() error = %v, want config-path rejection", err)
	}
}

func TestComposeGeneratorAcceptsAuthorizedEffectiveEnvFilePath(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	def := catalogPolicyTestDefinition()
	def.Permissions = append(def.Permissions, registry.PermissionConfigPath)
	def.Spec.Environment.EnvFile = []string{
		"{{ .Config.ConfigPath }}/service/runtime.env",
	}

	service, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err != nil {
		t.Fatal(err)
	}
	if len(service.EnvFile) != 1 ||
		service.EnvFile[0] != cfg.ConfigPath+"/service/runtime.env" {
		t.Fatalf("EnvFile = %#v", service.EnvFile)
	}
}

func TestComposeGeneratorRejectsUndeclaredEffectiveNetwork(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	def := catalogPolicyTestDefinition()
	def.Permissions = nil

	_, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err == nil || !strings.Contains(err.Error(), "network:app") {
		t.Fatalf("generateService() error = %v, want network permission rejection", err)
	}
}

func TestComposeGeneratorRejectsUndeclaredServiceNetwork(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	def := catalogPolicyTestDefinition()
	def.Spec.Networking.ModeTemplate = `service:gluetun`

	_, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err == nil || !strings.Contains(err.Error(), "service-network:gluetun") {
		t.Fatalf("generateService() error = %v, want service-network rejection", err)
	}
}

func TestComposeGeneratorAcceptsAuthorizedEffectivePathsAndServiceNetwork(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	def := catalogPolicyTestDefinition()
	def.Permissions = []string{
		registry.PermissionConfigPath,
		"network:" + registry.NetworkApplication,
		"service-network:gluetun",
	}
	def.Spec.Volumes = []registry.VolumeMount{{
		HostPath:      "{{ .Config.ConfigPath }}/service",
		ContainerPath: "/config",
	}}
	def.Spec.Networking.ModeTemplate = `{{ print "service:" "gluetun" }}`

	service, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err != nil {
		t.Fatalf("generateService() failed: %v", err)
	}
	if len(service.Volumes) != 1 ||
		service.Volumes[0] != cfg.ConfigPath+"/service:/config" {
		t.Fatalf("Volumes = %#v, want canonical authorized config mount", service.Volumes)
	}
	if service.NetworkMode != "service:gluetun" {
		t.Fatalf("NetworkMode = %q, want service:gluetun", service.NetworkMode)
	}
}

func TestComposeGeneratorPreservesAuthorizedRelativeBindMount(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	cfg.ConfigPath = "./configs"
	def := catalogPolicyTestDefinition()
	def.Permissions = []string{
		registry.PermissionConfigPath,
		"network:" + registry.NetworkApplication,
	}
	def.Spec.Volumes = []registry.VolumeMount{{
		HostPath:      "{{ .Config.ConfigPath }}/service",
		ContainerPath: "/config",
	}}

	service, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err != nil {
		t.Fatalf("generateService() failed: %v", err)
	}
	if len(service.Volumes) != 1 ||
		service.Volumes[0] != "./configs/service:/config" {
		t.Fatalf(
			"Volumes = %#v, want portable project-relative bind mount",
			service.Volumes,
		)
	}
}

func TestComposeGeneratorRejectsRenderedMountSeparator(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	def := catalogPolicyTestDefinition()
	def.Permissions = []string{registry.PermissionConfigPath}
	def.Spec.Volumes = []registry.VolumeMount{{
		HostPath:      `{{ .Config.ConfigPath }}{{ print ":" "ro" }}`,
		ContainerPath: "/config",
	}}

	_, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err == nil || !strings.Contains(err.Error(), "mount separator") {
		t.Fatalf("generateService() error = %v, want mount separator rejection", err)
	}
}

func TestComposeGeneratorRejectsRenderedPathThroughSymlinkedParent(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	if err := os.MkdirAll(cfg.ConfigPath, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(cfg.ConfigPath, "escape")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	def := catalogPolicyTestDefinition()
	def.Permissions = []string{registry.PermissionConfigPath}
	def.Spec.Volumes = []registry.VolumeMount{{
		HostPath:      "{{ .Config.ConfigPath }}/escape/target",
		ContainerPath: "/config",
	}}

	_, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err == nil || !strings.Contains(err.Error(), registry.PermissionHostMount) {
		t.Fatalf(
			"generateService() error = %v, want symlink escape rejection",
			err,
		)
	}
}

func TestComposeGeneratorRejectsExactEffectiveDockerSocketMount(t *testing.T) {
	cfg := catalogPolicyTestConfig(t)
	def := catalogPolicyTestDefinition()
	def.Spec.Volumes = []registry.VolumeMount{{
		HostPath:      `{{ print "/var/run/" "docker.sock" }}`,
		ContainerPath: `{{ print "/var/run/" "docker.sock" }}`,
		ReadOnly:      true,
	}}

	_, err := NewComposeGenerator(cfg, nil).generateService(def)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("generateService() error = %v, want exact Docker socket rejection", err)
	}
}

func catalogPolicyTestConfig(t *testing.T) *config.Config {
	t.Helper()
	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ProjectDir = projectDir
	cfg.ConfigPath = projectDir + "/configs"
	cfg.DataPath = projectDir + "/data"
	cfg.DownloadsPath = projectDir + "/data/downloads"
	cfg.MediaPath = projectDir + "/data/media"
	cfg.SecretsPath = projectDir + "/secrets"
	return cfg
}

func catalogPolicyTestDefinition() *registry.ServiceDefinition {
	return &registry.ServiceDefinition{
		Metadata: registry.ServiceMetadata{Name: "external-service"},
		Permissions: []string{
			"network:" + registry.NetworkApplication,
		},
		Spec: registry.ServiceSpec{
			Image: registry.ImageSpec{
				Repository: "alpine",
				Tag:        "latest",
			},
			Container: registry.ContainerSpec{
				NameTemplate: "sdbx-{{ .Name }}",
			},
			Networking: registry.NetworkSpec{
				Networks: []registry.NetworkRef{{
					Name: registry.NetworkApplication,
				}},
			},
		},
	}
}
