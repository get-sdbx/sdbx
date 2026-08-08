package integrate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/get-sdbx/sdbx/internal/config"
)

type liveImageLock struct {
	Images []struct {
		Service    string `json:"service"`
		Repository string `json:"repository"`
		Platforms  []struct {
			Platform string `json:"platform"`
			Digest   string `json:"digest"`
		} `json:"platforms"`
	} `json:"images"`
}

func TestLiveLockedArrAuthentication(t *testing.T) {
	if os.Getenv("SDBX_LIVE_CONTAINER_TEST") != "1" {
		t.Skip("set SDBX_LIVE_CONTAINER_TEST=1 to validate locked *arr authentication")
	}
	lockBody, err := os.ReadFile(filepath.Join("..", "..", "services", "images.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock liveImageLock
	if err := json.Unmarshal(lockBody, &lock); err != nil {
		t.Fatal(err)
	}
	platform := "linux/" + runtime.GOARCH

	for _, spec := range arrManagedAuthSpecs {
		t.Run(spec.name, func(t *testing.T) {
			repository, digest := lockedLiveImage(t, &lock, spec.name, platform)
			projectRoot := t.TempDir()
			project := config.DefaultConfig()
			project.PUID = os.Getuid()
			project.PGID = os.Getgid()
			project.ConfigPath = filepath.Join(projectRoot, "configs")
			project.SecretsPath = filepath.Join(projectRoot, "secrets")
			project.ActiveServices = map[string]bool{spec.name: true}
			results, err := EnsureArrAPIKeys(project)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 || results[0].Err != nil {
				t.Fatalf("stage auth config = %#v", results)
			}
			apiKey, err := ReadArrAPIKey(project, spec.name)
			if err != nil || apiKey == "" {
				t.Fatalf("read staged API key = %q, %v", apiKey, err)
			}

			cidFile := filepath.Join(t.TempDir(), "container.cid")
			port := ArrPort(spec.name)
			envPrefix := strings.ToUpper(spec.name)
			run := exec.Command(
				"docker",
				"run",
				"--rm",
				"--detach",
				"--platform",
				platform,
				"--cidfile",
				cidFile,
				"--publish",
				fmt.Sprintf("127.0.0.1::%d", port),
				"--env",
				"PUID="+strconv.Itoa(project.PUID),
				"--env",
				"PGID="+strconv.Itoa(project.PGID),
				"--env",
				"TZ=Etc/UTC",
				"--env",
				envPrefix+"__AUTH__METHOD=Forms",
				"--env",
				envPrefix+"__AUTH__REQUIRED=Enabled",
				"--volume",
				filepath.Join(project.ConfigPath, spec.name)+":/config",
				repository+"@"+digest,
			)
			output, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("start locked %s image: %v\n%s", spec.name, err, output)
			}
			containerIDBody, err := os.ReadFile(cidFile)
			if err != nil {
				t.Fatal(err)
			}
			containerID := strings.TrimSpace(string(containerIDBody))
			t.Cleanup(func() {
				_ = exec.Command("docker", "rm", "--force", containerID).Run()
			})

			portOutput, err := exec.Command(
				"docker",
				"port",
				containerID,
				fmt.Sprintf("%d/tcp", port),
			).CombinedOutput()
			if err != nil {
				t.Fatalf("resolve published port: %v\n%s", err, portOutput)
			}
			published := strings.TrimSpace(string(portOutput))
			_, publishedPort, found := strings.Cut(published, ":")
			if !found {
				t.Fatalf("unexpected Docker port output %q", published)
			}
			if lastColon := strings.LastIndex(published, ":"); lastColon >= 0 {
				publishedPort = published[lastColon+1:]
			}
			baseURL := "http://127.0.0.1:" + publishedPort
			statusURL := baseURL + "/api/" + spec.apiVersion + "/system/status"
			waitForLiveArrAPI(t, statusURL, apiKey)

			integrationConfig := DefaultConfig()
			integrationConfig.ProjectConfig = project
			integrationConfig.Timeout = 5 * time.Second
			integrationConfig.RetryAttempts = 1
			integrationConfig.RetryDelay = 250 * time.Millisecond
			integrator := NewIntegrator(integrationConfig)
			action, err := integrator.ensureArrNativeAuthentication(
				context.Background(),
				spec,
				&ServiceConfig{
					Name:       spec.name,
					URL:        baseURL,
					ControlURL: baseURL,
					APIKey:     apiKey,
					Enabled:    true,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if action != "reconciled" {
				t.Fatalf("action = %q, want reconciled", action)
			}

			password, err := readOrCreateSecret(
				secretsFilePath(project, spec.secretFile),
				24,
				project.PUID,
				project.PGID,
			)
			if err != nil {
				t.Fatal(err)
			}
			valid, err := verifyArrFormsCredential(
				context.Background(),
				baseURL,
				arrManagedAdminUsername,
				password,
				5*time.Second,
			)
			if err != nil || !valid {
				t.Fatalf("managed Forms login valid=%t err=%v", valid, err)
			}
			assertLiveArrBoundary(t, baseURL, statusURL, apiKey)
		})
	}
}

func lockedLiveImage(
	t *testing.T,
	lock *liveImageLock,
	service, platform string,
) (string, string) {
	t.Helper()
	for _, image := range lock.Images {
		if image.Service != service {
			continue
		}
		for _, candidate := range image.Platforms {
			if candidate.Platform == platform {
				return image.Repository, candidate.Digest
			}
		}
	}
	t.Fatalf("no locked %s image for %s", service, platform)
	return "", ""
}

func waitForLiveArrAPI(t *testing.T, statusURL, apiKey string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		request, err := http.NewRequest(http.MethodGet, statusURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Api-Key", apiKey)
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("locked *arr API did not become ready: %s", statusURL)
}

func assertLiveArrBoundary(
	t *testing.T,
	baseURL, statusURL, apiKey string,
) {
	t.Helper()
	noRedirect := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	anonymous, err := noRedirect.Get(baseURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = anonymous.Body.Close()
	if anonymous.StatusCode == http.StatusOK {
		t.Fatal("anonymous Docker-network UI request was accepted")
	}

	for _, candidate := range []struct {
		key  string
		want int
	}{
		{key: apiKey, want: http.StatusOK},
		{key: "invalid-api-key", want: http.StatusUnauthorized},
	} {
		request, err := http.NewRequest(http.MethodGet, statusURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Api-Key", candidate.key)
		response, err := noRedirect.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != candidate.want {
			t.Fatalf(
				"API status with selected key = %d, want %d",
				response.StatusCode,
				candidate.want,
			)
		}
	}
}
