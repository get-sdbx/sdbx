// Package recovery coordinates semantically verified project restore flows.
package recovery

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"

	"github.com/get-sdbx/sdbx/internal/backup"
	"github.com/get-sdbx/sdbx/internal/config"
	verifiedproject "github.com/get-sdbx/sdbx/internal/project"
	"github.com/get-sdbx/sdbx/internal/registry"
	"gopkg.in/yaml.v3"
)

// RestoreHooks returns the transactional state-restore policy. Project intent,
// lock state, Compose, environment output, and generated policy always remain
// anchored to the already verified target. The optional relocation mode allows
// only config_path and secrets_path to differ in an otherwise identical
// archived project.
func RestoreHooks(
	ctx context.Context,
	projectDir string,
	reg *registry.Registry,
	cliVersion string,
	relocateManagedRoots bool,
) (backup.RestoreHooks, error) {
	if projectDir == "" {
		return backup.RestoreHooks{}, fmt.Errorf("project directory is required")
	}
	if reg == nil {
		return backup.RestoreHooks{}, fmt.Errorf("service registry is required")
	}
	if cliVersion == "" {
		return backup.RestoreHooks{}, fmt.Errorf("CLI version is required")
	}
	target, err := verifyProject(ctx, projectDir, reg, cliVersion)
	if err != nil {
		return backup.RestoreHooks{}, fmt.Errorf(
			"restore target must be a verified generated project: %w",
			err,
		)
	}
	validate := func(validationContext context.Context) error {
		_, err := verifyProject(
			validationContext,
			projectDir,
			reg,
			cliVersion,
		)
		return err
	}
	skipConfigPaths, err := registry.GeneratedConfigPaths(target.Lock)
	if err != nil {
		return backup.RestoreHooks{}, err
	}
	inspector := &stateRestoreInspector{
		projectDir:          projectDir,
		registry:            reg,
		targetConfig:        target.Config,
		targetLock:          target.Lock,
		allowRootRelocation: relocateManagedRoots,
	}
	return backup.RestoreHooks{
		PreserveProject:    true,
		SkipConfigPaths:    skipConfigPaths,
		InspectProjectFile: inspector.inspectProjectFile,
		ValidateArchive:    inspector.validateArchive,
		Validate:           validate,
		VerifiedRoots: &backup.ManagedRoots{
			ConfigPath:  target.Config.ConfigPath,
			SecretsPath: target.Config.SecretsPath,
		},
	}, nil
}

func verifyProject(
	ctx context.Context,
	projectDir string,
	reg *registry.Registry,
	cliVersion string,
) (*verifiedproject.Verified, error) {
	cfg, err := config.LoadFile(filepath.Join(projectDir, ".sdbx.yaml"))
	if err != nil {
		return nil, err
	}
	verified, err := verifiedproject.VerifyGeneratedRuntime(
		ctx,
		projectDir,
		cfg,
		reg,
		cliVersion,
	)
	if err != nil {
		return nil, err
	}
	return verified, nil
}

type stateRestoreInspector struct {
	projectDir          string
	registry            *registry.Registry
	targetConfig        *config.Config
	targetLock          *registry.LockFile
	allowRootRelocation bool
	archivedConfig      *config.Config
	archivedLock        *registry.LockFile
}

func (i *stateRestoreInspector) inspectProjectFile(
	name string,
	data []byte,
) error {
	switch name {
	case ".sdbx.yaml":
		cfg, err := config.Parse(data, i.projectDir)
		if err != nil {
			return err
		}
		i.archivedConfig = cfg
	case ".sdbx.lock":
		lock, err := registry.NewLoader().ParseLockFile(data)
		if err != nil {
			return err
		}
		if err := registry.ValidateLockFile(lock, true); err != nil {
			return err
		}
		i.archivedLock = lock
	}
	return nil
}

func (i *stateRestoreInspector) validateArchive() error {
	if i.archivedConfig == nil {
		return fmt.Errorf("archive does not contain .sdbx.yaml")
	}
	if i.archivedLock == nil {
		return fmt.Errorf("archive does not contain .sdbx.lock")
	}

	archivedConfig := *i.archivedConfig
	if i.allowRootRelocation {
		archivedConfig.ConfigPath = i.targetConfig.ConfigPath
		archivedConfig.SecretsPath = i.targetConfig.SecretsPath
	}
	archivedConfig.ProjectDir = ""
	archivedConfig.ActiveServices = nil
	targetConfig := *i.targetConfig
	targetConfig.ProjectDir = ""
	targetConfig.ActiveServices = nil
	archivedYAML, err := yaml.Marshal(&archivedConfig)
	if err != nil {
		return err
	}
	targetYAML, err := yaml.Marshal(&targetConfig)
	if err != nil {
		return err
	}
	if !bytes.Equal(archivedYAML, targetYAML) {
		allowedDifference := "no fields"
		if i.allowRootRelocation {
			allowedDifference = "config_path or secrets_path"
		}
		return fmt.Errorf(
			"archive project intent differs from the target; restore mode permits differences in %s",
			allowedDifference,
		)
	}

	archivedLock := *i.archivedLock
	if i.allowRootRelocation {
		archivedLock.Metadata.ConfigDigest = i.targetLock.Metadata.ConfigDigest
	}
	if diffs := i.registry.DiffLockFiles(&archivedLock, i.targetLock); len(diffs) > 0 {
		return fmt.Errorf(
			"archive lock is incompatible with the verified restore target: %s",
			diffs[0].Description,
		)
	}
	return nil
}
