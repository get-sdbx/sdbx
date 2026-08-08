package registry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/get-sdbx/sdbx/internal/config"
	"gopkg.in/yaml.v3"
)

// Resolver handles service resolution and dependency ordering
type Resolver struct {
	registry *Registry
}

// NewResolver creates a new Resolver
func NewResolver(registry *Registry) *Resolver {
	return &Resolver{registry: registry}
}

// Resolve resolves all services based on configuration
func (r *Resolver) Resolve(ctx context.Context, cfg *config.Config) (*ResolutionGraph, error) {
	graph := &ResolutionGraph{
		Services: make(map[string]*ResolvedService),
		Errors:   make([]ResolutionError, 0),
		Warnings: make([]ResolutionWarning, 0),
	}

	// Get all available services
	services, err := r.registry.ListServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	// Build service map
	serviceMap := make(map[string]ServiceInfo)
	for _, svc := range services {
		serviceMap[svc.Name] = svc
	}

	// Determine which services to include
	enabledServices := r.determineEnabledServices(ctx, cfg, serviceMap)

	// Resolve each enabled service
	serviceNames := make([]string, 0, len(enabledServices))
	for serviceName := range enabledServices {
		serviceNames = append(serviceNames, serviceName)
	}
	sort.Strings(serviceNames)
	for _, serviceName := range serviceNames {
		if err := r.resolveService(ctx, cfg, graph, serviceName); err != nil {
			graph.Errors = append(graph.Errors, ResolutionError{
				Service: serviceName,
				Message: "failed to resolve",
				Cause:   err,
			})
		}
	}

	// Calculate dependency order
	order, err := r.topologicalSort(graph)
	if err != nil {
		graph.Errors = append(graph.Errors, ResolutionError{
			Service: "",
			Message: "dependency resolution failed",
			Cause:   err,
		})
	}
	graph.Order = order

	return graph, nil
}

// determineEnabledServices determines which services should be enabled
func (r *Resolver) determineEnabledServices(ctx context.Context, cfg *config.Config, serviceMap map[string]ServiceInfo) map[string]bool {
	enabled := make(map[string]bool)

	for name, svc := range serviceMap {
		// Core services (not addons) are always candidates
		if !svc.IsAddon {
			enabled[name] = true
			continue
		}

		// Addons need to be explicitly enabled
		if cfg.IsAddonEnabled(name) {
			enabled[name] = true
		}
	}

	return enabled
}

// resolveService resolves a single service
func (r *Resolver) resolveService(ctx context.Context, cfg *config.Config, graph *ResolutionGraph, serviceName string) error {
	// Check if already resolved
	if _, exists := graph.Services[serviceName]; exists {
		return nil
	}

	// Get service definition
	def, source, err := r.registry.GetService(ctx, serviceName)
	if err != nil {
		return err
	}

	// Check conditions
	if !MatchesActivationConditions(def.Conditions, cfg) {
		return nil // Service doesn't meet conditions
	}

	hash := r.calculateHash(def)
	validationErrors := r.registry.ValidateForSource(def, source)
	for _, warning := range FilterBySeverity(validationErrors, "warning") {
		graph.Warnings = append(graph.Warnings, ResolutionWarning{
			Service: serviceName,
			Field:   warning.Field,
			Message: warning.Message,
		})
	}
	if HasErrors(validationErrors) {
		return fmt.Errorf("service definition validation failed: %s", formatValidationErrors(validationErrors))
	}

	// Get source path
	sourceProvider, _ := r.registry.GetSource(source)
	sourcePath := ""
	if sourceProvider != nil {
		sourcePath = sourceProvider.GetServicePath(serviceName)
	}

	// Create resolved service
	resolved := &ResolvedService{
		Name:            serviceName,
		Source:          source,
		SourcePath:      sourcePath,
		Definition:      def,
		DefinitionHash:  hash,
		FinalDefinition: def,
		Dependencies:    r.collectDependencies(def, cfg),
		Enabled:         true,
	}

	graph.Services[serviceName] = resolved

	// Recursively resolve dependencies
	for _, depName := range resolved.Dependencies {
		if err := r.resolveService(ctx, cfg, graph, depName); err != nil {
			graph.Errors = append(graph.Errors, ResolutionError{
				Service: serviceName,
				Message: fmt.Sprintf("dependency %s failed", depName),
				Cause:   err,
			})
			continue
		}
		if _, exists := graph.Services[depName]; !exists {
			graph.Errors = append(graph.Errors, ResolutionError{
				Service: serviceName,
				Message: fmt.Sprintf(
					"dependency %s is not enabled by the current configuration",
					depName,
				),
			})
		}
	}

	return nil
}

func formatValidationErrors(errors []ValidationError) string {
	var messages []string
	for _, err := range errors {
		if err.Severity == "error" {
			messages = append(messages, err.Error())
		}
	}
	return strings.Join(messages, "; ")
}

// collectDependencies collects all dependencies for a service
func (r *Resolver) collectDependencies(def *ServiceDefinition, cfg *config.Config) []string {
	deps := make(map[string]bool)

	// Required dependencies
	for _, dep := range def.Spec.Dependencies.Required {
		deps[dep] = true
	}

	// Conditional dependencies
	for _, dep := range def.Spec.Dependencies.Conditional {
		if evaluateDependencyCondition(dep.When, cfg) {
			deps[dep.Name] = true
		}
	}

	// Convert to slice
	result := make([]string, 0, len(deps))
	for dep := range deps {
		result = append(result, dep)
	}
	sort.Strings(result)

	return result
}

// calculateHash calculates a hash of the service definition
func (r *Resolver) calculateHash(def *ServiceDefinition) string {
	data, _ := yaml.Marshal(def)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", hash[:])
}

// topologicalSort performs topological sort on the dependency graph
func (r *Resolver) topologicalSort(graph *ResolutionGraph) ([]string, error) {
	// Build adjacency list
	inDegree := make(map[string]int)
	adjList := make(map[string][]string)

	for name, svc := range graph.Services {
		if _, exists := inDegree[name]; !exists {
			inDegree[name] = 0
		}
		if _, exists := adjList[name]; !exists {
			adjList[name] = []string{}
		}

		for _, dep := range svc.Dependencies {
			// Only count dependencies that are in our graph
			if _, exists := graph.Services[dep]; exists {
				adjList[dep] = append(adjList[dep], name)
				inDegree[name]++
			}
		}
	}

	// Kahn's algorithm
	var queue []string
	for name, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}
	sort.Strings(queue)
	for name := range adjList {
		sort.Strings(adjList[name])
	}

	var order []string
	for len(queue) > 0 {
		// Pop from queue
		node := queue[0]
		queue = queue[1:]
		order = append(order, node)

		// Reduce in-degree for dependents
		for _, dependent := range adjList[node] {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
				sort.Strings(queue)
			}
		}
	}

	// Check for cycles
	if len(order) != len(graph.Services) {
		return nil, fmt.Errorf("circular dependency detected")
	}

	return order, nil
}

// ResolveService resolves a single service by name
func (r *Resolver) ResolveService(ctx context.Context, cfg *config.Config, serviceName string) (*ResolvedService, error) {
	graph := &ResolutionGraph{
		Services: make(map[string]*ResolvedService),
		Errors:   make([]ResolutionError, 0),
		Warnings: make([]ResolutionWarning, 0),
	}

	if err := r.resolveService(ctx, cfg, graph, serviceName); err != nil {
		return nil, err
	}

	resolved, exists := graph.Services[serviceName]
	if !exists {
		return nil, fmt.Errorf("service %s not found after resolution", serviceName)
	}

	return resolved, nil
}

// GetDependencyOrder returns services in dependency order
func GetDependencyOrder(graph *ResolutionGraph) []string {
	return graph.Order
}

// GetEnabledServices returns only enabled services
func GetEnabledServices(graph *ResolutionGraph) map[string]*ResolvedService {
	enabled := make(map[string]*ResolvedService)
	for name, svc := range graph.Services {
		if svc.Enabled {
			enabled[name] = svc
		}
	}
	return enabled
}
