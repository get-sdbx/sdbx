package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/generator"
	verifiedproject "github.com/get-sdbx/sdbx/internal/project"
	"github.com/get-sdbx/sdbx/internal/registry"
)

type projectContext struct {
	Dir      string
	Config   *config.Config
	Registry *registry.Registry
}

type verifiedProject struct {
	Project *projectContext
	Lock    *registry.LockFile
	Graph   *registry.ResolutionGraph
}

func newProjectContext() (*projectContext, error) {
	projectDir, err := config.ProjectDir()
	if err != nil {
		return nil, err
	}
	if err := generator.RecoverProjectTransaction(projectDir); err != nil {
		return nil, fmt.Errorf("recover interrupted project transaction: %w", err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err := os.Chdir(projectDir); err != nil {
		return nil, fmt.Errorf("failed to change directory: %w", err)
	}
	defer os.Chdir(originalDir)

	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load project configuration: %w", err)
	}

	reg, err := getRegistry()
	if err != nil {
		return nil, err
	}

	return &projectContext{
		Dir:      projectDir,
		Config:   cfg,
		Registry: reg,
	}, nil
}

func loadProjectLock(projectDir string) (*registry.LockFile, error) {
	return verifiedproject.LoadLock(projectDir)
}

func verifyProjectLock(ctx context.Context, project *projectContext) (*registry.LockFile, error) {
	verified, err := verifiedproject.Verify(
		ctx,
		project.Dir,
		project.Config,
		project.Registry,
		Version,
	)
	if err != nil {
		return nil, err
	}
	return verified.Lock, nil
}

func loadVerifiedProject(ctx context.Context) (*verifiedProject, error) {
	project, err := newProjectContext()
	if err != nil {
		return nil, err
	}
	verified, err := verifiedproject.Verify(
		ctx,
		project.Dir,
		project.Config,
		project.Registry,
		Version,
	)
	if err != nil {
		return nil, err
	}
	return &verifiedProject{
		Project: project,
		Lock:    verified.Lock,
		Graph:   verified.Graph,
	}, nil
}
