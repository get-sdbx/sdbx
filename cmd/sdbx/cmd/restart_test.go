package cmd

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/get-sdbx/sdbx/internal/docker"
)

type recordingRestarter struct {
	services []docker.Service
	calls    []string
	waitErr  map[string]error
}

func (r *recordingRestarter) PS(context.Context) ([]docker.Service, error) {
	r.calls = append(r.calls, "ps")
	return r.services, nil
}

func (r *recordingRestarter) Restart(_ context.Context, service string) error {
	r.calls = append(r.calls, "restart:"+service)
	return nil
}

func (r *recordingRestarter) WaitHealthy(
	_ context.Context,
	service string,
	_ time.Duration,
) error {
	r.calls = append(r.calls, "wait:"+service)
	return r.waitErr[service]
}

func TestRestartGluetunRejoinsQbittorrentNamespace(t *testing.T) {
	compose := &recordingRestarter{
		services: []docker.Service{
			{Service: "gluetun"},
			{Service: "qbittorrent"},
		},
	}
	dependentRestarted, err := restartService(
		context.Background(),
		compose,
		"gluetun",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !dependentRestarted {
		t.Fatal("qBittorrent dependent restart was not reported")
	}
	want := []string{
		"ps",
		"restart:gluetun",
		"wait:gluetun",
		"restart:qbittorrent",
		"wait:qbittorrent",
	}
	if !reflect.DeepEqual(compose.calls, want) {
		t.Fatalf("calls = %#v, want %#v", compose.calls, want)
	}
}

func TestRestartGluetunWithoutQbittorrentStopsAfterGluetun(t *testing.T) {
	compose := &recordingRestarter{
		services: []docker.Service{{Service: "gluetun"}},
	}
	dependentRestarted, err := restartService(
		context.Background(),
		compose,
		"gluetun",
	)
	if err != nil {
		t.Fatal(err)
	}
	if dependentRestarted {
		t.Fatal("unexpected dependent restart")
	}
	want := []string{"ps", "restart:gluetun"}
	if !reflect.DeepEqual(compose.calls, want) {
		t.Fatalf("calls = %#v, want %#v", compose.calls, want)
	}
}

func TestRestartAllWaitsForVPNBeforeRejoiningQbittorrent(t *testing.T) {
	compose := &recordingRestarter{
		services: []docker.Service{
			{Service: "authelia"},
			{Service: "gluetun"},
			{Service: "qbittorrent"},
		},
	}
	dependentRestarted, err := restartAllServices(context.Background(), compose)
	if err != nil {
		t.Fatal(err)
	}
	if !dependentRestarted {
		t.Fatal("qBittorrent dependent restart was not reported")
	}
	want := []string{
		"ps",
		"restart:",
		"wait:gluetun",
		"restart:qbittorrent",
		"wait:qbittorrent",
	}
	if !reflect.DeepEqual(compose.calls, want) {
		t.Fatalf("calls = %#v, want %#v", compose.calls, want)
	}
}

func TestRestartGluetunDoesNotRestartQbittorrentBeforeVPNHealthy(t *testing.T) {
	compose := &recordingRestarter{
		services: []docker.Service{
			{Service: "gluetun"},
			{Service: "qbittorrent"},
		},
		waitErr: map[string]error{
			"gluetun": errors.New("synthetic health failure"),
		},
	}
	dependentRestarted, err := restartService(
		context.Background(),
		compose,
		"gluetun",
	)
	if err == nil {
		t.Fatal("expected Gluetun health failure")
	}
	if dependentRestarted {
		t.Fatal("dependent restart reported despite Gluetun failure")
	}
	want := []string{"ps", "restart:gluetun", "wait:gluetun"}
	if !reflect.DeepEqual(compose.calls, want) {
		t.Fatalf("calls = %#v, want %#v", compose.calls, want)
	}
}
