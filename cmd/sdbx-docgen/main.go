// Command sdbx-docgen writes or checks deterministic public references.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/get-sdbx/sdbx/internal/docgen"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sdbx-docgen: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		check bool
		write bool
		root  string
	)
	flag.BoolVar(&check, "check", false, "fail when checked-in generated documentation is stale")
	flag.BoolVar(&write, "write", false, "write generated documentation")
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

	outputs, err := docgen.GenerateAll()
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(outputs))
	for path := range outputs {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, relative := range paths {
		destination := filepath.Join(root, filepath.FromSlash(relative))
		expected := outputs[relative]
		if check {
			// #nosec G304 -- destination is selected from the generator's
			// fixed output map beneath the repository root.
			actual, err := os.ReadFile(destination)
			if err != nil {
				return fmt.Errorf("%s is missing or unreadable: %w", relative, err)
			}
			if !bytes.Equal(actual, expected) {
				return fmt.Errorf("%s is stale; run 'make docs'", relative)
			}
			fmt.Printf("verified %s\n", relative)
			continue
		}
		// #nosec G301 -- generated documentation is intentionally public.
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return fmt.Errorf("create %s parent: %w", relative, err)
		}
		// #nosec G306 -- generated documentation is intentionally public.
		if err := os.WriteFile(destination, expected, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", relative, err)
		}
		fmt.Printf("wrote %s\n", relative)
	}
	return nil
}
