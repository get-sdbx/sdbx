package httplifecycle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServeStopsCleanlyAfterCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "ok")
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Serve(ctx, server, listener, time.Second)
	}()

	response, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	cancel()

	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP server did not stop after cancellation")
	}
}

func TestServeGroupRunsEveryEndpointAndStopsTogether(t *testing.T) {
	listeners := make([]net.Listener, 2)
	endpoints := make([]Endpoint, 2)
	for index := range listeners {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners[index] = listener
		endpoints[index] = Endpoint{
			Name:     fmt.Sprintf("endpoint-%d", index),
			Listener: listener,
			Server: &http.Server{Handler: http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					_, _ = io.WriteString(w, "ok")
				},
			)},
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- ServeGroup(ctx, endpoints, time.Second)
	}()
	for _, listener := range listeners {
		response, err := http.Get("http://" + listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP endpoint group did not stop after cancellation")
	}
}

func TestServeGroupCancelsPeersAfterEndpointFailure(t *testing.T) {
	peerListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("synthetic grouped accept failure")
	err = ServeGroup(
		context.Background(),
		[]Endpoint{
			{
				Name:     "failed",
				Server:   &http.Server{},
				Listener: &failingListener{err: sentinel},
			},
			{
				Name:     "peer",
				Server:   &http.Server{},
				Listener: peerListener,
			},
		},
		time.Second,
	)
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), `"failed"`) {
		t.Fatalf("ServeGroup() error = %v, want named endpoint failure", err)
	}
}

func TestServeGroupRejectsInvalidEndpointBeforeStarting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	err = ServeGroup(
		context.Background(),
		[]Endpoint{
			{Name: "valid", Server: &http.Server{}, Listener: listener},
			{Name: "missing-server", Listener: &failingListener{err: net.ErrClosed}},
		},
		time.Second,
	)
	if err == nil || !strings.Contains(err.Error(), "missing-server") {
		t.Fatalf("ServeGroup() error = %v, want validation failure", err)
	}
	if closeErr := listener.Close(); closeErr != nil {
		t.Fatalf("valid endpoint started before validation completed: %v", closeErr)
	}
}

func TestServeReturnsListenerFailureWithoutWaitingForContext(t *testing.T) {
	sentinel := errors.New("synthetic accept failure")
	listener := &failingListener{err: sentinel}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Serve(ctx, &http.Server{}, listener, time.Second)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Serve() error = %v, want listener failure", err)
	}
}

func TestServeReportsShutdownTimeoutAndForceClosesConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(started)
			<-release
			_, _ = io.WriteString(w, "late")
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Serve(ctx, server, listener, 20*time.Millisecond)
	}()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		response, requestErr := http.Get("http://" + listener.Addr().String())
		if requestErr == nil {
			_ = response.Body.Close()
		}
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach the handler")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) ||
			!strings.Contains(err.Error(), "graceful HTTP shutdown") {
			t.Fatalf("Serve() error = %v, want explicit shutdown timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP server did not force-close after shutdown timeout")
	}
	close(release)
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("force-closed request did not return")
	}
}

func TestServeRejectsInvalidLifecycleInputs(t *testing.T) {
	listener := &failingListener{err: net.ErrClosed}
	tests := []struct {
		name     string
		ctx      context.Context
		server   *http.Server
		listener net.Listener
		timeout  time.Duration
	}{
		{
			name:     "nil context",
			server:   &http.Server{},
			listener: listener,
			timeout:  time.Second,
		},
		{
			name:     "nil server",
			ctx:      context.Background(),
			listener: listener,
			timeout:  time.Second,
		},
		{
			name:    "nil listener",
			ctx:     context.Background(),
			server:  &http.Server{},
			timeout: time.Second,
		},
		{
			name:     "nonpositive timeout",
			ctx:      context.Background(),
			server:   &http.Server{},
			listener: listener,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Serve(
				test.ctx,
				test.server,
				test.listener,
				test.timeout,
			); err == nil {
				t.Fatal("invalid lifecycle input was accepted")
			}
		})
	}
}

type failingListener struct {
	err error
}

func (l *failingListener) Accept() (net.Conn, error) {
	return nil, l.err
}

func (*failingListener) Close() error {
	return nil
}

func (*failingListener) Addr() net.Addr {
	return syntheticAddr("synthetic")
}

type syntheticAddr string

func (a syntheticAddr) Network() string {
	return string(a)
}

func (a syntheticAddr) String() string {
	return string(a)
}
