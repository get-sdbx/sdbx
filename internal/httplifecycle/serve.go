// Package httplifecycle coordinates bounded HTTP server startup and shutdown.
package httplifecycle

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Endpoint binds one HTTP server to one already-created listener.
type Endpoint struct {
	Name     string
	Server   *http.Server
	Listener net.Listener
}

// ServeGroup runs every endpoint as one lifecycle. A failure in any endpoint
// cancels and joins all peers before returning, while parent cancellation
// performs the same bounded graceful shutdown used by Serve.
func ServeGroup(
	ctx context.Context,
	endpoints []Endpoint,
	shutdownTimeout time.Duration,
) error {
	if ctx == nil {
		return fmt.Errorf("HTTP server context is required")
	}
	if len(endpoints) == 0 {
		return fmt.Errorf("at least one HTTP endpoint is required")
	}
	if shutdownTimeout <= 0 {
		return fmt.Errorf("HTTP shutdown timeout must be positive")
	}

	type endpointResult struct {
		name string
		err  error
	}
	groupCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan endpointResult, len(endpoints))
	names := make([]string, len(endpoints))
	for index, endpoint := range endpoints {
		name := strings.TrimSpace(endpoint.Name)
		if name == "" {
			return fmt.Errorf("HTTP endpoint %d has no name", index)
		}
		if endpoint.Server == nil {
			return fmt.Errorf("HTTP endpoint %q has no server", name)
		}
		if endpoint.Listener == nil {
			return fmt.Errorf("HTTP endpoint %q has no listener", name)
		}
		names[index] = name
	}
	for index, endpoint := range endpoints {
		name := names[index]
		go func(endpoint Endpoint, name string) {
			results <- endpointResult{
				name: name,
				err: Serve(
					groupCtx,
					endpoint.Server,
					endpoint.Listener,
					shutdownTimeout,
				),
			}
		}(endpoint, name)
	}

	remaining := len(endpoints)
	var joined error
	select {
	case <-ctx.Done():
		cancel()
	case result := <-results:
		remaining--
		if result.err == nil {
			result.err = fmt.Errorf("endpoint stopped unexpectedly")
		}
		joined = errors.Join(
			joined,
			fmt.Errorf("serve HTTP endpoint %q: %w", result.name, result.err),
		)
		cancel()
	}
	for remaining > 0 {
		result := <-results
		remaining--
		if result.err != nil {
			joined = errors.Join(
				joined,
				fmt.Errorf("serve HTTP endpoint %q: %w", result.name, result.err),
			)
		}
	}
	return joined
}

// Serve runs server on listener until serving fails or ctx is canceled.
//
// Cancellation starts a bounded graceful shutdown. If that deadline expires,
// active connections are closed and the shutdown error is returned. The
// serving goroutine is always joined before Serve returns.
func Serve(
	ctx context.Context,
	server *http.Server,
	listener net.Listener,
	shutdownTimeout time.Duration,
) error {
	if ctx == nil {
		return fmt.Errorf("HTTP server context is required")
	}
	if server == nil {
		return fmt.Errorf("HTTP server is required")
	}
	if listener == nil {
		return fmt.Errorf("HTTP listener is required")
	}
	if shutdownTimeout <= 0 {
		return fmt.Errorf("HTTP shutdown timeout must be positive")
	}

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- normalizeServeError(server.Serve(listener))
	}()

	select {
	case err := <-serveResult:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			shutdownTimeout,
		)
		shutdownErr := server.Shutdown(shutdownCtx)
		cancel()

		if shutdownErr != nil {
			closeErr := server.Close()
			if errors.Is(closeErr, net.ErrClosed) {
				closeErr = nil
			}
			serveErr := <-serveResult
			return errors.Join(
				fmt.Errorf("graceful HTTP shutdown: %w", shutdownErr),
				wrapError("force-close HTTP server", closeErr),
				wrapError("serve HTTP after failed shutdown", serveErr),
			)
		}

		return <-serveResult
	}
}

func normalizeServeError(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func wrapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
