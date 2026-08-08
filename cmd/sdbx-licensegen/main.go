// Command sdbx-licensegen writes or checks the release third-party notices.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/get-sdbx/sdbx/internal/licensegen"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sdbx-licensegen: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		check bool
		write bool
		root  string
	)
	flag.BoolVar(&check, "check", false, "fail when THIRD_PARTY_NOTICES.txt is stale")
	flag.BoolVar(&write, "write", false, "write THIRD_PARTY_NOTICES.txt")
	flag.StringVar(&root, "root", ".", "repository root")
	flag.Parse()
	if check == write {
		return fmt.Errorf("select exactly one of --check or --write")
	}

	root, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return fmt.Errorf("repository root does not contain go.mod: %w", err)
	}
	expected, err := licensegen.Generate(context.Background(), root)
	if err != nil {
		return err
	}
	destination := filepath.Join(root, "THIRD_PARTY_NOTICES.txt")
	if check {
		actual, err := securefs.ReadRegularFileAt(
			root,
			filepath.Base(destination),
			64<<20,
		)
		if err != nil {
			return fmt.Errorf("THIRD_PARTY_NOTICES.txt is missing or unreadable: %w", err)
		}
		if !bytes.Equal(actual, expected) {
			return fmt.Errorf(
				"THIRD_PARTY_NOTICES.txt is stale; run 'make licenses'",
			)
		}
		fmt.Println("verified THIRD_PARTY_NOTICES.txt")
		return nil
	}

	if err := securefs.WriteFileAtomicAt(
		root,
		filepath.Base(destination),
		expected,
		0o644,
	); err != nil {
		return fmt.Errorf("write THIRD_PARTY_NOTICES.txt: %w", err)
	}
	fmt.Println("wrote THIRD_PARTY_NOTICES.txt")
	return nil
}
