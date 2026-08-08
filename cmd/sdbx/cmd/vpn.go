package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/get-sdbx/sdbx/internal/vpn"
	"github.com/spf13/cobra"
)

var vpnCmd = &cobra.Command{
	Use:   "vpn",
	Short: "Inspect download VPN protection",
}

var vpnStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Verify Gluetun health and compare host and tunnel egress",
	Args:  cobra.NoArgs,
	RunE:  runVPNStatus,
}

func init() {
	vpnCmd.AddCommand(vpnStatusCmd)
	rootCmd.AddCommand(vpnCmd)
}

func runVPNStatus(command *cobra.Command, _ []string) error {
	project, err := newProjectContext()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(commandContext(command), 10*time.Second)
	defer cancel()

	status := vpn.NewChecker(project.Dir).Check(ctx, project.Config)
	if IsJSONOutput() {
		data, marshalErr := json.MarshalIndent(status, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("encode VPN status: %w", marshalErr)
		}
		fmt.Println(string(data))
	} else {
		fmt.Println(tui.TitleStyle.Render("SDBX VPN Status"))
		fmt.Println()
		fmt.Printf("  Configured:       %t\n", status.Configured)
		fmt.Printf("  Gluetun healthy:  %t\n", status.GluetunHealthy)
		fmt.Printf("  Peer port:        %d/tcp+udp\n", status.TorrentPeerPort)
		if status.HostEgressIP != "" {
			fmt.Printf("  Host egress:      %s\n", status.HostEgressIP)
		}
		if status.TunnelEgressIP != "" {
			fmt.Printf("  Tunnel egress:    %s\n", status.TunnelEgressIP)
		}
		fmt.Printf("  Protection proven: %t\n", status.ProtectionProven)
		fmt.Println()
		if status.ProtectionProven {
			fmt.Println(tui.SuccessStyle.Render("✓ " + status.Message))
		} else {
			fmt.Println(tui.ErrorStyle.Render("✗ " + status.Message))
		}
	}

	if !status.ProtectionProven {
		return fmt.Errorf("VPN protection not proven: %s", status.Message)
	}
	return nil
}
