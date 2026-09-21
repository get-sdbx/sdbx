package generator

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/get-sdbx/sdbx/internal/registry"
)

func (g *ComposeGenerator) buildDevices(def *registry.ServiceDefinition, ctx TemplateContext) ([]string, error) {
	devices := append([]string(nil), def.Spec.Container.Devices...)
	for index, device := range def.Spec.Container.ConditionalDevices {
		if !declaresCatalogPermission(def, registry.PermissionDevice) {
			return nil, fmt.Errorf("conditional device requires catalog permission %q", registry.PermissionDevice)
		}
		matches, err := evalCatalogCondition(device.When, ctx)
		if err != nil {
			return nil, fmt.Errorf("evaluate conditional device %d: %w", index, err)
		}
		if !matches {
			continue
		}
		rendered, err := renderCatalogTemplate(device.Device, ctx)
		if err != nil {
			return nil, fmt.Errorf("render conditional device %d: %w", index, err)
		}
		if err := validateConditionalDevice(rendered); err != nil {
			return nil, fmt.Errorf("conditional device %d: %w", index, err)
		}
		devices = append(devices, rendered)
	}
	return devices, nil
}

func validateConditionalDevice(value string) error {
	parts := strings.Split(value, ":")
	if len(parts) < 1 || len(parts) > 3 || strings.ContainsAny(value, "\x00\r\n\t ") {
		return fmt.Errorf("invalid device mapping")
	}
	paths := parts
	if len(parts) == 3 {
		if parts[2] == "" || strings.Trim(parts[2], "rwm") != "" {
			return fmt.Errorf("invalid device permissions")
		}
		paths = parts[:2]
	}
	for _, path := range paths {
		if !strings.HasPrefix(path, "/dev/") || filepath.Clean(path) != path || path == "/dev/mem" || path == "/dev/kmem" {
			return fmt.Errorf("device paths must be canonical, safe paths under /dev")
		}
	}
	return nil
}
