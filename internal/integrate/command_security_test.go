package integrate

import (
	"strings"
	"testing"
	"time"
)

func TestFilebrowserPasswordNeverAppearsInHostDockerArguments(t *testing.T) {
	const canary = "sdbx-canary-secret-filebrowser"

	for _, action := range []string{"update", "add"} {
		t.Run(action, func(t *testing.T) {
			args := filebrowserPasswordCommandArgs(action)
			joined := strings.Join(args, "\x00")

			if strings.Contains(joined, canary) {
				t.Fatalf("Docker arguments contain password canary: %q", args)
			}
			if !strings.Contains(joined, `"$sdbx_password"`) {
				t.Fatalf("wrapper does not reference the stdin-backed shell variable: %q", args)
			}
			if strings.Contains(joined, "set -x") {
				t.Fatalf("wrapper enables shell tracing and could disclose the password: %q", args)
			}
		})
	}
}

func TestWizarrSecretsNeverAppearInHostDockerArguments(t *testing.T) {
	const canary = "sdbx-canary-secret-wizarr"
	args := wizarrReconcileCommandArgs()
	joined := strings.Join(args, "\x00")
	if strings.Contains(joined, canary) {
		t.Fatal("Wizarr credential appeared in Docker arguments")
	}
	if len(args) < 4 || args[3] != "/app/.venv/bin/python" {
		t.Fatalf("Wizarr reconciliation executable = %#v", args)
	}
	if !strings.Contains(wizarrReconcileScript, `print("ok", flush=True)`) ||
		!strings.Contains(wizarrReconcileScript, "os._exit(0)") {
		t.Fatal("Wizarr reconciliation does not force a bounded exit after commit")
	}
	if wizarrReconcileTimeout <= 0 || wizarrReconcileTimeout > time.Minute {
		t.Fatalf("Wizarr reconciliation timeout = %s", wizarrReconcileTimeout)
	}
}

func TestWizarrReconcileOutputAcceptsOnlyTrailingSuccessMarker(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{name: "plain", output: "ok\n", want: true},
		{name: "startup banner", output: "startup progress\nready\nok\n", want: true},
		{name: "missing", output: "startup progress\n", want: false},
		{name: "trailing failure", output: "ok\nlate failure\n", want: false},
		{name: "empty", output: "\n", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := wizarrReconcileOutputOK([]byte(test.output)); got != test.want {
				t.Fatalf("wizarrReconcileOutputOK() = %t, want %t", got, test.want)
			}
		})
	}
}
