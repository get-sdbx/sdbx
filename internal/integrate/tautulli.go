package integrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/securefs"
)

const tautulliConfigMaxSize = 4 << 20

type tautulliConfigState struct {
	PMSIP    string
	PMSPort  string
	PMSToken string
	PMSSSL   string
}

func readTautulliConfig(path string) ([]byte, tautulliConfigState, error) {
	body, err := securefs.ReadRegularFile(path, tautulliConfigMaxSize)
	if err != nil {
		return nil, tautulliConfigState{}, err
	}
	state := tautulliConfigState{}
	section := ""
	seen := map[string]bool{}
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if section != "pms" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if key != "pms_ip" && key != "pms_port" && key != "pms_token" && key != "pms_ssl" {
			continue
		}
		if seen[key] {
			wipeCredentialBytes(body)
			return nil, tautulliConfigState{}, fmt.Errorf("duplicate Tautulli PMS setting %s", key)
		}
		seen[key] = true
		value := strings.TrimSpace(parts[1])
		switch key {
		case "pms_ip":
			state.PMSIP = value
		case "pms_port":
			state.PMSPort = value
		case "pms_token":
			state.PMSToken = value
		case "pms_ssl":
			state.PMSSSL = value
		}
	}
	return body, state, nil
}

func renderTautulliPMSConfig(body []byte, token string) ([]byte, error) {
	lines := strings.Split(string(body), "\n")
	section := ""
	foundSection := false
	desired := map[string]string{
		"pms_ip":    "sdbx-plex",
		"pms_port":  "32400",
		"pms_token": token,
		"pms_ssl":   "0",
	}
	seen := map[string]bool{}
	sectionEnd := -1
	for index, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if section == "pms" && sectionEnd < 0 {
				sectionEnd = index
			}
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "pms" {
				foundSection = true
			}
			continue
		}
		if section != "pms" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value, managed := desired[key]
		if !managed {
			continue
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate Tautulli PMS setting %s", key)
		}
		seen[key] = true
		lines[index] = key + " = " + value
	}
	if !foundSection {
		return nil, fmt.Errorf("Tautulli PMS section is unavailable")
	}
	if sectionEnd < 0 {
		sectionEnd = len(lines)
	}
	missing := make([]string, 0, 4)
	for _, key := range []string{"pms_ip", "pms_port", "pms_token", "pms_ssl"} {
		if !seen[key] {
			missing = append(missing, key+" = "+desired[key])
		}
	}
	if len(missing) > 0 {
		updated := make([]string, 0, len(lines)+len(missing))
		updated = append(updated, lines[:sectionEnd]...)
		updated = append(updated, missing...)
		updated = append(updated, lines[sectionEnd:]...)
		lines = updated
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func (i *Integrator) integrateTautulli(ctx context.Context) *IntegrationResult {
	result := &IntegrationResult{Service: "tautulli → plex"}
	token, err := ReadPlexToken(i.config.ProjectConfig)
	if err != nil || token == "" {
		result.Message = "Failed to read Plex application token"
		result.Error = err
		if err == nil {
			result.Error = fmt.Errorf("Plex application token is unavailable")
		}
		return result
	}
	path := filepath.Join(i.config.ProjectConfig.ConfigPath, "tautulli", "config.ini")
	body, state, err := readTautulliConfig(path)
	if err != nil {
		result.Message, result.Error = "Failed to read Tautulli settings", err
		return result
	}
	defer wipeCredentialBytes(body)
	currentMatches := state.PMSIP == "sdbx-plex" && state.PMSPort == "32400" &&
		state.PMSSSL == "0" && state.PMSToken == token
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		result.Message, result.Error = "Tautulli settings path is unsafe", statErr
		return result
	}
	if currentMatches && info.Mode().Perm() == 0o600 {
		result.Success, result.Message = true, "Already configured with private settings"
		return result
	}
	if i.config.DryRun {
		result.Success, result.Message = true, "[DRY RUN] Would repair Plex connection and private settings mode"
		return result
	}
	updated, err := renderTautulliPMSConfig(body, token)
	if err != nil {
		result.Message, result.Error = "Failed to render Tautulli settings", err
		return result
	}
	defer wipeCredentialBytes(updated)
	if i.stop == nil || i.start == nil {
		result.Message, result.Error = "Service lifecycle handler is unavailable", fmt.Errorf("Tautulli lifecycle handler is unavailable")
		return result
	}
	if err := i.stop(ctx, "tautulli"); err != nil {
		result.Message, result.Error = "Failed to stop Tautulli safely", err
		return result
	}
	rollback := func() error {
		writeErr := writeFileChown(
			path,
			body,
			info.Mode().Perm(),
			i.config.ProjectConfig.PUID,
			i.config.ProjectConfig.PGID,
		)
		startErr := i.start(ctx, "tautulli")
		if writeErr != nil {
			return writeErr
		}
		return startErr
	}
	if err := writeFileChown(
		path,
		updated,
		0o600,
		i.config.ProjectConfig.PUID,
		i.config.ProjectConfig.PGID,
	); err != nil {
		_ = i.start(ctx, "tautulli")
		result.Message, result.Error = "Failed to write Tautulli settings", err
		return result
	}
	if err := i.start(ctx, "tautulli"); err != nil {
		rollbackErr := rollback()
		result.Message = "Failed to restart Tautulli; settings rollback attempted"
		result.Error = fmt.Errorf("restart Tautulli: %w; rollback: %v", err, rollbackErr)
		return result
	}
	deadline := time.Now().Add(60 * time.Second)
	var healthErr error
	for time.Now().Before(deadline) {
		healthErr = i.checkServiceHealth(ctx, "tautulli", i.services["tautulli"])
		if healthErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			healthErr = ctx.Err()
			deadline = time.Time{}
		case <-time.After(time.Second):
		}
	}
	if healthErr != nil {
		rollbackErr := rollback()
		result.Message = "Tautulli failed health verification; settings rollback attempted"
		result.Error = fmt.Errorf("verify Tautulli: %w; rollback: %v", healthErr, rollbackErr)
		return result
	}
	verifiedBody, verified, err := readTautulliConfig(path)
	wipeCredentialBytes(verifiedBody)
	if err != nil || verified.PMSIP != "sdbx-plex" || verified.PMSPort != "32400" ||
		verified.PMSSSL != "0" || verified.PMSToken != token {
		rollbackErr := rollback()
		result.Message = "Tautulli settings failed read-back verification; rollback attempted"
		result.Error = errors.Join(err, rollbackErr)
		if err == nil {
			result.Error = errors.Join(
				fmt.Errorf("Tautulli PMS settings mismatch"),
				rollbackErr,
			)
		}
		return result
	}
	result.Success, result.Message = true, "Repaired, restarted, and verified"
	return result
}
