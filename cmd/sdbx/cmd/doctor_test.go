package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/doctor"
)

func TestDoctorCommand(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-doctor-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Change to temp directory
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)

	// Save original stdout
	oldStdout := os.Stdout
	defer func() { os.Stdout = oldStdout }()

	// Capture output
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Missing project files are a failed diagnostic and must produce a
	// nonzero command result.
	if err := runDoctor(doctorCmd, []string{}); err == nil {
		t.Fatal("runDoctor succeeded with failed diagnostics")
	}

	// Close writer and read output
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output contains expected elements
	if !strings.Contains(output, "SDBX Doctor") {
		t.Error("Output should contain 'SDBX Doctor' header")
	}
	if !strings.Contains(output, "checks") {
		t.Error("Output should mention checks")
	}
}

func TestDoctorCommandJSON(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "sdbx-doctor-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Change to temp directory
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)

	// Save original stdout and json flag
	oldStdout := os.Stdout
	oldJSON := jsonOut
	defer func() {
		os.Stdout = oldStdout
		jsonOut = oldJSON
	}()

	// Enable JSON output
	jsonOut = true

	// Capture output
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Missing project files are expected to fail while still producing a
	// complete JSON report.
	if err := runDoctor(doctorCmd, []string{}); err == nil {
		t.Fatal("runDoctor succeeded with failed diagnostics")
	}

	// Close writer and read output
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Parse JSON output
	var report doctorJSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, output)
	}

	// Verify JSON structure
	if len(report.Checks) == 0 {
		t.Error("JSON output should contain at least one check")
	}
	if report.Healthy {
		t.Error("JSON report should not be healthy without project files")
	}
	if report.Summary.Failed == 0 {
		t.Error("JSON summary should count failed checks")
	}

	// Verify check structure
	for _, check := range report.Checks {
		if check.Name == "" {
			t.Error("Check should have a name")
		}
		if check.Status == "" {
			t.Error("Check should have a string status")
		}
	}
}

func TestDoctorWithoutProject(t *testing.T) {
	// Create temp directory without project files
	tmpDir, err := os.MkdirTemp("", "sdbx-doctor-noproject-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Change to temp directory (no .sdbx.yaml)
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)

	// Save original stdout
	oldStdout := os.Stdout
	defer func() { os.Stdout = oldStdout }()

	// Capture output
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Execute doctor command. It should complete the report but fail its
	// process contract because required project state is absent.
	if err := runDoctor(doctorCmd, []string{}); err == nil {
		t.Fatal("runDoctor succeeded without required project state")
	}

	// Close writer and read output
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should still run checks
	if !strings.Contains(output, "SDBX Doctor") {
		t.Error("Output should contain header even without project")
	}
}

func TestDoctorReportRedactsCredentialBearingMessages(t *testing.T) {
	const canary = "DOCTOR_SECRET_CANARY"
	report := buildDoctorReport([]doctor.Check{{
		Name:    "synthetic",
		Status:  doctor.StatusFailed,
		Message: "upstream failed with token=" + canary,
	}})
	if len(report.Checks) != 1 {
		t.Fatalf("checks = %#v", report.Checks)
	}
	if strings.Contains(report.Checks[0].Message, canary) ||
		!strings.Contains(report.Checks[0].Message, "[REDACTED]") {
		t.Fatalf("doctor report leaked credential: %#v", report.Checks[0])
	}
}
