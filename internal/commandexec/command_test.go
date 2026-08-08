package commandexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCombinedOutputBoundsAndCancelsSubprocess(t *testing.T) {
	started := time.Now()
	output, err := CombinedOutput(
		context.Background(),
		1_024,
		nil,
		os.Args[0],
		"-test.run=TestCombinedOutputHelperProcess",
		"--",
		"oversized",
	)
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("CombinedOutput error = %v, want output limit", err)
	}
	if output != nil {
		t.Fatalf("CombinedOutput returned %d hostile bytes", len(output))
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("oversized subprocess was not canceled promptly: %s", elapsed)
	}
}

func TestCombinedOutputPreservesBoundedFailureOutput(t *testing.T) {
	output, err := CombinedOutput(
		context.Background(),
		1_024,
		nil,
		os.Args[0],
		"-test.run=TestCombinedOutputHelperProcess",
		"--",
		"failure",
	)
	if err == nil {
		t.Fatal("CombinedOutput accepted failing subprocess")
	}
	if string(output) != "bounded failure\n" {
		t.Fatalf("CombinedOutput = %q", output)
	}
}

func TestCombinedOutputHelperProcess(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		return
	}
	switch os.Args[separator+1] {
	case "oversized":
		for {
			_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", 8_192))
		}
	case "failure":
		_, _ = fmt.Fprintln(os.Stderr, "bounded failure")
		os.Exit(17)
	default:
		os.Exit(2)
	}
}
