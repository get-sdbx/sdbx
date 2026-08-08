// Package main is the entry point for the sdbx CLI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/get-sdbx/sdbx/cmd/sdbx/cmd"
)

// Version information set by goreleaser
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, date)
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	if err := cmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
