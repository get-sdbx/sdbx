package broker

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/get-sdbx/sdbx/internal/httplifecycle"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

type UnixServerOptions struct {
	SocketPath string
	SocketMode os.FileMode
	SocketGID  *int
}

func ServeUnix(
	ctx context.Context,
	handler http.Handler,
	options UnixServerOptions,
) (returnErr error) {
	if handler == nil {
		return fmt.Errorf("broker handler is required")
	}
	if !filepath.IsAbs(options.SocketPath) {
		return fmt.Errorf("broker socket path must be absolute")
	}
	socketPath := filepath.Clean(options.SocketPath)
	parent := filepath.Dir(socketPath)
	if err := securefs.EnsureDir(parent, 0o750); err != nil {
		return fmt.Errorf("prepare broker socket directory: %w", err)
	}
	parentRoot, _, err := securefs.OpenVerifiedRoot(parent)
	if err != nil {
		return fmt.Errorf("pin broker socket directory: %w", err)
	}
	defer parentRoot.Close()
	parentHandle, err := parentRoot.Open(".")
	if err != nil {
		return fmt.Errorf("open broker socket directory: %w", err)
	}
	defer parentHandle.Close()
	if err := parentHandle.Chmod(0o750); err != nil {
		return fmt.Errorf("set broker socket directory mode: %w", err)
	}
	if options.SocketGID != nil {
		uid := -1
		if os.Geteuid() == 0 {
			uid = 0
		}
		if err := parentHandle.Chown(uid, *options.SocketGID); err != nil {
			return fmt.Errorf("set broker socket directory group: %w", err)
		}
	}
	socketName := filepath.Base(socketPath)
	if _, err := parentRoot.Lstat(socketName); err == nil {
		return fmt.Errorf(
			"broker socket already exists at %s; verify no daemon is running before removing it",
			socketPath,
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect broker socket: %w", err)
	}

	mode := options.SocketMode
	if mode == 0 {
		mode = 0o660
	}
	if mode.Perm()&0o007 != 0 {
		return fmt.Errorf("broker socket mode must not grant access to other users")
	}

	// Bind outside the published path so the process umask can never expose a
	// reachable socket before its final group and mode are applied.
	privateName, err := createSocketStagingDirectory(parentRoot)
	if err != nil {
		return fmt.Errorf("prepare private broker socket staging directory: %w", err)
	}
	privateDir := filepath.Join(parent, privateName)
	stagedSocketPath := filepath.Join(privateDir, "s")
	defer func() {
		returnErr = errors.Join(
			returnErr,
			removeSocketPath(
				parentRoot,
				filepath.Join(privateName, "s"),
				"remove staged broker socket",
			),
			removeSocketPath(
				parentRoot,
				privateName,
				"remove broker socket staging directory",
			),
		)
	}()
	listener, err := net.Listen("unix", stagedSocketPath)
	if err != nil {
		return fmt.Errorf("listen on staged broker socket: %w", err)
	}
	defer func() {
		closeErr := listener.Close()
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}
		if closeErr != nil {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("close broker listener: %w", closeErr),
			)
		}
	}()
	if err := os.Chmod(stagedSocketPath, mode.Perm()); err != nil {
		return fmt.Errorf("set broker socket mode: %w", err)
	}
	if options.SocketGID != nil {
		if err := os.Chown(stagedSocketPath, -1, *options.SocketGID); err != nil {
			return fmt.Errorf("set broker socket group: %w", err)
		}
	}
	if err := parentRoot.Rename(filepath.Join(privateName, "s"), socketName); err != nil {
		return fmt.Errorf("publish broker socket: %w", err)
	}
	defer func() {
		returnErr = errors.Join(
			returnErr,
			removeSocketPath(parentRoot, socketName, "remove published broker socket"),
		)
	}()
	published, err := parentRoot.Lstat(socketName)
	if err != nil {
		return fmt.Errorf("inspect published broker socket: %w", err)
	}
	if published.Mode()&os.ModeSocket == 0 ||
		published.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("published broker socket has an unsafe type or mode")
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      6 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	return httplifecycle.Serve(ctx, server, listener, 10*time.Second)
}

func removeSocketPath(root *os.Root, path, operation string) error {
	if err := root.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

func createSocketStagingDirectory(parent *os.Root) (string, error) {
	if parent == nil {
		return "", fmt.Errorf("socket staging root is required")
	}
	for range 16 {
		var suffix [2]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", fmt.Errorf("generate staging directory name: %w", err)
		}
		candidate := fmt.Sprintf(".s%x", suffix)
		if err := parent.Mkdir(candidate, 0o700); err == nil {
			return candidate, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("no private staging directory name is available")
}
