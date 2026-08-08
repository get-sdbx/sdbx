// Package commandexec runs fixed executable vectors with bounded output.
package commandexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

var ErrOutputLimit = errors.New("command output exceeded the byte limit")

// CombinedOutput runs one executable without a shell and retains at most
// byteLimit bytes across stdout and stderr. Exceeding the limit cancels the
// subprocess and returns no attacker-controlled partial output.
func CombinedOutput(
	ctx context.Context,
	byteLimit int,
	input io.Reader,
	name string,
	args ...string,
) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("command context is required")
	}
	if byteLimit <= 0 {
		return nil, fmt.Errorf("command output limit must be positive")
	}
	commandContext, cancel := context.WithCancel(ctx)
	defer cancel()
	// #nosec G204 -- callers pass a fixed executable and distinct reviewed
	// arguments; this helper never invokes a shell.
	command := exec.CommandContext(commandContext, name, args...)
	command.Stdin = input
	command.WaitDelay = 2 * time.Second
	output := &boundedBuffer{
		limit:  byteLimit,
		cancel: cancel,
	}
	command.Stdout = output
	command.Stderr = output
	runErr := command.Run()
	if output.Exceeded() {
		return nil, ErrOutputLimit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return output.Bytes(), runErr
}

type boundedBuffer struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (w *boundedBuffer) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := w.limit - w.buffer.Len()
	if remaining > 0 {
		writeLength := len(data)
		if writeLength > remaining {
			writeLength = remaining
		}
		_, _ = w.buffer.Write(data[:writeLength])
	}
	if len(data) > remaining && !w.exceeded {
		w.exceeded = true
		w.cancel()
	}
	return len(data), nil
}

func (w *boundedBuffer) Exceeded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exceeded
}

func (w *boundedBuffer) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buffer.Bytes())
}
