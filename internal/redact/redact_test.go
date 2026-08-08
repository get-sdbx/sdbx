package redact

import (
	"bytes"
	"strings"
	"testing"
)

func TestTextRedactsCredentialShapes(t *testing.T) {
	const canary = "SDBX_SECRET_CANARY_7Qx9"
	inputs := []string{
		"password=" + canary,
		"OPENVPN_PASSWORD=" + canary,
		`{"api_key":"` + canary + `"}`,
		"Authorization: Bearer " + canary,
		"Basic " + canary,
		"Cookie: session=" + canary,
		"--identity-file /private/" + canary,
		"https://user:" + canary + "@example.test/path",
		"https://example.test/callback?access_token=" + canary + "&ok=yes",
		"A temporary password is provided for this session: " + canary,
		"User 'admin' initialized with randomly generated password: " + canary,
		"<ApiKey>" + canary + "</ApiKey>",
		"AGE-SECRET-KEY-1" + strings.Repeat("A", 32),
		"-----BEGIN PRIVATE KEY-----\n" + canary +
			"\n-----END PRIVATE KEY-----",
	}
	for _, input := range inputs {
		t.Run(input[:min(len(input), 24)], func(t *testing.T) {
			output := Text(input)
			if strings.Contains(output, canary) {
				t.Fatalf("redacted text still contains canary: %q", output)
			}
			if !strings.Contains(output, Replacement) &&
				!strings.Contains(output, "[REDACTED PRIVATE KEY]") {
				t.Fatalf("redacted text has no marker: %q", output)
			}
		})
	}
}

func TestValuesRedactsUnlabelledKnownValue(t *testing.T) {
	const canary = "UNLABELLED_SECRET_CANARY"
	if output := Values("upstream echoed "+canary, canary); strings.Contains(
		output,
		canary,
	) {
		t.Fatalf("known value survived: %q", output)
	}
}

func TestTextPreservesOrdinaryOperationalText(t *testing.T) {
	const input = "service tokenization completed; secret scanning passed"
	if output := Text(input); output != input {
		t.Fatalf("ordinary text changed from %q to %q", input, output)
	}
}

func TestLineWriterRedactsAcrossWritesAndFlushesFinalLine(t *testing.T) {
	var output bytes.Buffer
	writer := NewLineWriter(&output)
	for _, fragment := range []string{
		"startup\npass",
		"word=SPLIT_CANARY",
		"\nfinal token=FINAL_CANARY",
	} {
		if _, err := writer.Write([]byte(fragment)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result := output.String()
	for _, canary := range []string{"SPLIT_CANARY", "FINAL_CANARY"} {
		if strings.Contains(result, canary) {
			t.Fatalf("stream output leaked %s: %q", canary, result)
		}
	}
	if !strings.Contains(result, "startup\n") ||
		strings.Count(result, Replacement) != 2 {
		t.Fatalf("unexpected stream output: %q", result)
	}
}

func TestLineWriterReplacesOversizedLine(t *testing.T) {
	var output bytes.Buffer
	writer := NewLineWriter(&output)
	oversized := "password=OVERSIZED_CANARY_" +
		strings.Repeat("x", maxBufferedLineBytes)
	if _, err := writer.Write([]byte(oversized)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("\nnext\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result := output.String()
	if strings.Contains(result, "OVERSIZED_CANARY") ||
		!strings.Contains(result, "[REDACTED OVERSIZED LOG LINE]\nnext\n") {
		t.Fatalf("unexpected oversized-line output: %q", result)
	}
}
