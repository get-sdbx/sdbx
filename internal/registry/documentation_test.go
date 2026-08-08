package registry

import (
	"os"
	"strings"
	"testing"
)

func TestServiceCatalogDocumentationExampleIsValid(t *testing.T) {
	document, err := os.ReadFile("../../services/README.md")
	if err != nil {
		t.Fatal(err)
	}
	const heading = "## Minimal addon"
	sectionStart := strings.Index(string(document), heading)
	if sectionStart < 0 {
		t.Fatalf("%s section is missing", heading)
	}
	section := string(document)[sectionStart:]
	const fence = "```yaml\n"
	yamlStart := strings.Index(section, fence)
	if yamlStart < 0 {
		t.Fatal("minimal addon YAML fence is missing")
	}
	yamlStart += len(fence)
	yamlEnd := strings.Index(section[yamlStart:], "\n```")
	if yamlEnd < 0 {
		t.Fatal("minimal addon YAML fence is not closed")
	}

	definition, err := NewLoader().ParseServiceDefinition(
		[]byte(section[yamlStart : yamlStart+yamlEnd]),
	)
	if err != nil {
		t.Fatalf("parse documented service definition: %v", err)
	}
	for _, validationErr := range NewValidator().Validate(definition) {
		if validationErr.Severity == "error" {
			t.Errorf(
				"documented service definition %s: %s",
				validationErr.Field,
				validationErr.Message,
			)
		}
	}
}
