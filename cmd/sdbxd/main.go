// Package main is the root-owned SDBX management broker daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/get-sdbx/sdbx/internal/broker"
	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/management"
	"github.com/get-sdbx/sdbx/internal/redact"
	"github.com/get-sdbx/sdbx/internal/registry"
	"github.com/get-sdbx/sdbx/internal/routing"
	"github.com/get-sdbx/sdbx/internal/secrets"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type daemonOptions struct {
	projectDir       string
	sources          string
	socket           string
	tokenFile        string
	consoleTokenFile string
	socketGroup      string
	auditLog         string
	oidcIssuer       string
	oidcClientID     string
	showVersion      bool
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sdbxd: %s\n", redact.Text(err.Error()))
		os.Exit(1)
	}
}

func run() (returnErr error) {
	options := parseFlags()
	if options.showVersion {
		fmt.Printf("sdbxd %s (commit %s, built %s)\n", version, commit, date)
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root because it owns host and Docker operations")
	}
	if strings.TrimSpace(options.projectDir) == "" {
		return fmt.Errorf("--project-dir is required")
	}
	projectDir, err := filepath.Abs(options.projectDir)
	if err != nil {
		return fmt.Errorf("resolve project directory: %w", err)
	}
	groupID, err := resolveGroupID(options.socketGroup)
	if err != nil {
		return err
	}

	cfg, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}
	reg, err := loadRegistry(options.sources)
	if err != nil {
		return err
	}
	operator, err := management.NewProjectOperator(
		projectDir,
		version,
		reg,
		registry.NewOfficialImageDigestResolver(
			registry.NewDockerImageDigestResolver(),
		),
	)
	if err != nil {
		return fmt.Errorf("verify registered project: %w", err)
	}
	if cfg.ProjectDir != projectDir {
		return fmt.Errorf("project configuration resolved outside the registered project")
	}

	token, err := broker.EnsureTokenFile(broker.TokenFileOptions{
		Path: options.tokenFile,
		GID:  &groupID,
	})
	if err != nil {
		return err
	}
	consoleToken, err := broker.EnsureTokenFile(broker.TokenFileOptions{
		Path: options.consoleTokenFile,
		GID:  &groupID,
	})
	if err != nil {
		return fmt.Errorf("provision browser console credential: %w", err)
	}
	if consoleToken == token {
		return fmt.Errorf("browser and broker credentials must be distinct")
	}
	secretsDir := cfg.SecretsPath
	if !filepath.IsAbs(secretsDir) {
		secretsDir = filepath.Join(projectDir, secretsDir)
	}
	if err := secrets.ProvisionConsoleRuntime(
		filepath.Clean(secretsDir),
		filepath.Dir(options.consoleTokenFile),
		routing.SharedHostname(cfg),
		groupID,
	); err != nil {
		return fmt.Errorf("provision remote console trust: %w", err)
	}
	staticAuthorizer, err := broker.NewStaticTokenAuthorizer(token)
	if err != nil {
		return err
	}
	authorizers := []broker.Authorizer{staticAuthorizer}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	// Warm the read-only Docker status path after daemon startup so the first
	// Dashboard visit does not pay the Docker CLI and Compose cold-start cost.
	// The broker remains available even when this best-effort warmup fails.
	go func() {
		warmCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, _ = operator.Services(warmCtx)
	}()
	if options.oidcIssuer != "" || options.oidcClientID != "" {
		oidcAuthorizer, err := broker.NewOIDCAuthorizer(ctx, broker.OIDCOptions{
			Issuer:   options.oidcIssuer,
			ClientID: options.oidcClientID,
		})
		if err != nil {
			return err
		}
		authorizers = append(authorizers, oidcAuthorizer)
	}
	authorizer, err := broker.NewAnyAuthorizer(authorizers...)
	if err != nil {
		return err
	}
	auditor, err := broker.OpenFileAuditor(options.auditLog)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := auditor.Close(); closeErr != nil {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("close management audit log: %w", closeErr),
			)
		}
	}()
	server, err := broker.NewServer(
		operator,
		authorizer,
		broker.WithAuditor(auditor),
	)
	if err != nil {
		return err
	}

	fmt.Printf(
		"sdbxd %s serving project %s on %s\n",
		version,
		projectDir,
		options.socket,
	)
	return broker.ServeUnix(ctx, server.Handler(), broker.UnixServerOptions{
		SocketPath: options.socket,
		SocketMode: 0o660,
		SocketGID:  &groupID,
	})
}

func parseFlags() daemonOptions {
	var options daemonOptions
	flag.StringVar(&options.projectDir, "project-dir", "", "absolute SDBX project directory")
	flag.StringVar(&options.sources, "sources", "", "optional service source configuration file")
	flag.StringVar(&options.socket, "socket", "/var/run/sdbx/sdbxd.sock", "management Unix socket")
	flag.StringVar(&options.tokenFile, "token-file", "/var/run/sdbx/client.token", "management client token file")
	flag.StringVar(
		&options.consoleTokenFile,
		"console-token-file",
		"/var/run/sdbx/console.token",
		"out-of-band browser console token file",
	)
	flag.StringVar(&options.socketGroup, "socket-group", "sdbx", "group allowed to access the broker")
	flag.StringVar(&options.auditLog, "audit-log", "/var/log/sdbx/audit.jsonl", "append-only audit log")
	flag.StringVar(&options.oidcIssuer, "oidc-issuer", "", "optional Authelia OIDC issuer")
	flag.StringVar(&options.oidcClientID, "oidc-client-id", "", "optional Authelia OIDC client ID")
	flag.BoolVar(&options.showVersion, "version", false, "print version information")
	flag.Parse()
	return options
}

func resolveGroupID(identifier string) (int, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return 0, fmt.Errorf("--socket-group is required")
	}
	if numeric, err := strconv.Atoi(identifier); err == nil {
		if numeric < 0 {
			return 0, fmt.Errorf("socket group ID must be non-negative")
		}
		return numeric, nil
	}
	group, err := user.LookupGroup(identifier)
	if err != nil {
		return 0, fmt.Errorf(
			"management group %q does not exist; create it before starting sdbxd",
			identifier,
		)
	}
	numeric, err := strconv.Atoi(group.Gid)
	if err != nil || numeric < 0 {
		return 0, fmt.Errorf("management group %q has an invalid group ID", identifier)
	}
	return numeric, nil
}

func loadRegistry(path string) (*registry.Registry, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return registry.NewDefaultRegistry()
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve source configuration: %w", err)
	}
	sourceConfig, err := registry.NewLoader().LoadSourceConfig(absolute)
	if err != nil {
		return nil, fmt.Errorf("load source configuration: %w", err)
	}
	reg, err := registry.New(sourceConfig)
	if err != nil {
		return nil, fmt.Errorf("create service registry: %w", err)
	}
	return reg, nil
}
