package config

import (
	"net"
	"net/netip"
	"regexp"
	"strconv"
)

// PlexConfig contains opt-in host access for Plex. Empty settings preserve
// container-only access and do not expose a GPU or a native HTTP listener.
type PlexConfig struct {
	HardwareDevice string `mapstructure:"hardware_device" yaml:"hardware_device,omitempty" json:"hardwareDevice,omitempty"`
	AMDVAAPI       bool   `mapstructure:"amd_vaapi" yaml:"amd_vaapi,omitempty" json:"amdVaapi,omitempty"`
	LANAddress     string `mapstructure:"lan_address" yaml:"lan_address,omitempty" json:"lanAddress,omitempty"`
	LANPort        int    `mapstructure:"lan_port" yaml:"lan_port,omitempty" json:"lanPort,omitempty"`
}

var drmRenderDevicePattern = regexp.MustCompile(`^/dev/dri/renderD[0-9]{1,5}$`)

func (p PlexConfig) Validate() error {
	if p.HardwareDevice != "" && !drmRenderDevicePattern.MatchString(p.HardwareDevice) {
		return NewValidationError("plex.hardware_device", "must be a canonical /dev/dri/renderD<number> device path or empty to disable")
	}
	if p.AMDVAAPI && p.HardwareDevice == "" {
		return NewValidationError("plex.amd_vaapi", "requires plex.hardware_device; the AMD compatibility package is opt-in")
	}
	if p.LANAddress != "" {
		address, err := netip.ParseAddr(p.LANAddress)
		if err != nil || address.Zone() != "" || address.Is4In6() || (!address.IsPrivate() && !address.IsLoopback()) {
			return NewValidationError("plex.lan_address", "must be a private or loopback IP address, or empty to disable; wildcard and public addresses are not allowed")
		}
	}
	if p.LANPort < 0 || p.LANPort > 65535 {
		return NewValidationError("plex.lan_port", "must be between 1 and 65535, or 0 for the default 32400")
	}
	return nil
}

func (p PlexConfig) EffectiveLANPort() int {
	if p.LANPort == 0 {
		return 32400
	}
	return p.LANPort
}

// LANBinding returns only the validated host side of a Compose port mapping.
func (p PlexConfig) LANBinding() string {
	if p.LANAddress == "" {
		return ""
	}
	return net.JoinHostPort(p.LANAddress, strconv.Itoa(p.EffectiveLANPort()))
}
