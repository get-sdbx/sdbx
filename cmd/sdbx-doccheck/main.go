// Command sdbx-doccheck validates documentation links and typed examples.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/get-sdbx/sdbx/internal/doccheck"
)

func main() {
	var root string
	flag.StringVar(&root, "root", ".", "repository root")
	flag.Parse()

	findings := doccheck.Check(root)
	if len(findings) > 0 {
		_, _ = fmt.Fprintf(
			os.Stderr,
			"documentation validation failed:\n%s",
			doccheck.Format(findings),
		)
		os.Exit(1)
	}
	fmt.Println("documentation validation passed")
}
