package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/docker"
	"github.com/get-sdbx/sdbx/internal/tui"
	"github.com/spf13/cobra"
)

var restartCmd = &cobra.Command{
	Use:   "restart [service...]",
	Short: "Restart SDBX services",
	Long: `Restart one or all SDBX services.

Examples:
  sdbx restart          # Restart all services
  sdbx restart plex     # Restart only Plex
  sdbx restart sonarr prowlarr  # Restart multiple services`,
	RunE: runRestart,
}

func init() {
	rootCmd.AddCommand(restartCmd)
}

func runRestart(command *cobra.Command, args []string) error {
	// Find project directory
	projectDir, err := config.ProjectDir()
	if err != nil {
		return err
	}

	compose := docker.NewCompose(projectDir)
	ctx := command.Context()

	if len(args) == 0 {
		fmt.Println(tui.InfoStyle.Render("Restarting all services..."))
		start := time.Now()

		if _, err := restartAllServices(ctx, compose); err != nil {
			return fmt.Errorf("failed to restart services: %w", err)
		}

		fmt.Println()
		fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("✓ All services restarted in %s", time.Since(start).Round(time.Millisecond))))
	} else {
		var restartErrors []error
		restartedByDependency := map[string]bool{}
		for _, service := range args {
			if restartedByDependency[service] {
				fmt.Printf(
					"Skipping %s: already restarted after its VPN dependency\n",
					service,
				)
				continue
			}
			fmt.Printf("Restarting %s...\n", service)
			dependentRestarted, err := restartService(ctx, compose, service)
			if err != nil {
				fmt.Println(tui.ErrorStyle.Render(fmt.Sprintf(
					"  ✗ Failed to restart %s: %s",
					service,
					redactCLIError(err.Error()),
				)))
				restartErrors = append(restartErrors, fmt.Errorf("%s: %w", service, err))
			} else {
				message := fmt.Sprintf("  ✓ %s restarted", service)
				if dependentRestarted {
					restartedByDependency["qbittorrent"] = true
					message += " (qBittorrent rejoined the VPN network namespace)"
				}
				fmt.Println(tui.SuccessStyle.Render(message))
			}
		}
		if len(restartErrors) > 0 {
			return fmt.Errorf("one or more services failed to restart: %w", errors.Join(restartErrors...))
		}
	}

	return nil
}

const vpnDependentRestartTimeout = 2 * time.Minute

type composeRestarter interface {
	PS(context.Context) ([]docker.Service, error)
	Restart(context.Context, string) error
	WaitHealthy(context.Context, string, time.Duration) error
}

func restartService(
	ctx context.Context,
	compose composeRestarter,
	service string,
) (dependentRestarted bool, err error) {
	if service != "gluetun" {
		return false, compose.Restart(ctx, service)
	}

	services, err := compose.PS(ctx)
	if err != nil {
		return false, fmt.Errorf("inspect VPN dependents: %w", err)
	}
	restartQbittorrent := composeServiceExists(services, "qbittorrent")

	if err := compose.Restart(ctx, "gluetun"); err != nil {
		return false, err
	}
	if !restartQbittorrent {
		return false, nil
	}
	if err := compose.WaitHealthy(
		ctx,
		"gluetun",
		vpnDependentRestartTimeout,
	); err != nil {
		return false, fmt.Errorf("wait for Gluetun before restarting qBittorrent: %w", err)
	}
	if err := compose.Restart(ctx, "qbittorrent"); err != nil {
		return false, fmt.Errorf("restart qBittorrent VPN dependent: %w", err)
	}
	if err := compose.WaitHealthy(
		ctx,
		"qbittorrent",
		vpnDependentRestartTimeout,
	); err != nil {
		return false, fmt.Errorf("wait for qBittorrent after VPN restart: %w", err)
	}
	return true, nil
}

func restartAllServices(
	ctx context.Context,
	compose composeRestarter,
) (dependentRestarted bool, err error) {
	services, err := compose.PS(ctx)
	if err != nil {
		return false, fmt.Errorf("inspect VPN dependents: %w", err)
	}
	restartVPNDependent := composeServiceExists(services, "gluetun") &&
		composeServiceExists(services, "qbittorrent")

	if err := compose.Restart(ctx, ""); err != nil {
		return false, err
	}
	if !restartVPNDependent {
		return false, nil
	}
	if err := compose.WaitHealthy(
		ctx,
		"gluetun",
		vpnDependentRestartTimeout,
	); err != nil {
		return false, fmt.Errorf("wait for Gluetun before rejoining qBittorrent: %w", err)
	}
	if err := compose.Restart(ctx, "qbittorrent"); err != nil {
		return false, fmt.Errorf("restart qBittorrent VPN dependent: %w", err)
	}
	if err := compose.WaitHealthy(
		ctx,
		"qbittorrent",
		vpnDependentRestartTimeout,
	); err != nil {
		return false, fmt.Errorf("wait for qBittorrent after VPN restart: %w", err)
	}
	return true, nil
}

func composeServiceExists(services []docker.Service, service string) bool {
	for _, candidate := range services {
		if candidate.Service == service {
			return true
		}
	}
	return false
}
