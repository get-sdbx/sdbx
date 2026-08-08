// Command sdbx-imageaudit emits the immutable OCI inventory used by the
// maintainer-only catalog image audit.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/get-sdbx/sdbx/internal/imageaudit"
	"github.com/get-sdbx/sdbx/internal/registry"
	officialservices "github.com/get-sdbx/sdbx/services"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "catalog image inventory failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("sdbx-imageaudit", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	embedded := flags.Bool(
		"embedded",
		false,
		"emit the reviewed image snapshot embedded in the binary",
	)
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}

	signalContext, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, 15*time.Minute)
	defer cancel()

	definitions, err := registry.NewEmbeddedSource().Load(ctx)
	if err != nil {
		return fmt.Errorf("load embedded catalog: %w", err)
	}
	if *embedded {
		resolver := registry.NewOfficialImageDigestResolver(nil)
		for _, definition := range definitions {
			if _, err := resolver.Resolve(
				ctx,
				definition.Spec.Image.Repository,
				definition.Spec.Image.Tag,
			); err != nil {
				return fmt.Errorf(
					"validate embedded image snapshot for %s: %w",
					definition.Metadata.Name,
					err,
				)
			}
		}
		if _, err := os.Stdout.Write(officialservices.ImageLock); err != nil {
			return fmt.Errorf("write embedded image snapshot: %w", err)
		}
		return nil
	}

	inventory, err := imageaudit.Build(
		ctx,
		definitions,
		registry.NewDockerImageDigestResolver(),
	)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(inventory); err != nil {
		return fmt.Errorf("encode inventory: %w", err)
	}
	return nil
}
