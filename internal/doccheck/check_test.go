package doccheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckAcceptsLinksAnchorsAndTypedFences(t *testing.T) {
	root := t.TempDir()
	writeTestDocument(t, root, "README.md", `# Project

[Guide](docs/guide.md#safe-example)

`+"```bash"+`
value="synthetic"
printf '%s\n' "$value"
`+"```"+`
`)
	writeTestDocument(t, root, "docs/guide.md", `# Guide

## Safe example

`+"```yaml"+`
enabled: true
items:
  - one
`+"```"+`

`+"```json"+`
{"ok": true}
`+"```"+`
`)

	if findings := Check(root); len(findings) != 0 {
		t.Fatalf("Check() findings:\n%s", Format(findings))
	}
}

func TestCheckRejectsBrokenDocumentation(t *testing.T) {
	root := t.TempDir()
	writeTestDocument(t, root, "README.md", `# Project

[Missing](docs/guide.md#missing)

`+"```bash"+`
if true; then
`+"```"+`
`)
	writeTestDocument(t, root, "docs/guide.md", "# Guide\n")

	findings := Check(root)
	formatted := Format(findings)
	for _, expected := range []string{"missing internal anchor", "invalid shell fence"} {
		if !strings.Contains(formatted, expected) {
			t.Fatalf("Check() = %q, want %q", formatted, expected)
		}
	}
}

func TestCheckIgnoresRepositoryArtifactRoots(t *testing.T) {
	root := t.TempDir()
	writeTestDocument(t, root, "README.md", "# Project\n")
	writeTestDocument(t, root, "output/upstream/README.md", `# Upstream

[Broken](missing.md#anchor)

`+"```bash"+`
if true; then
`+"```"+`
`)
	writeTestDocument(t, root, ".test/runtime/README.md", `# Runtime

[Broken](missing.md)
`)

	if findings := Check(root); len(findings) != 0 {
		t.Fatalf("Check() findings:\n%s", Format(findings))
	}
}

func writeTestDocument(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
