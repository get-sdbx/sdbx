package integrate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type profilarrClient struct {
	client *HTTPClient
	config *ServiceConfig
}

type profilarrInstance struct {
	ID                     int     `json:"id"`
	Name                   string  `json:"name"`
	Type                   string  `json:"type"`
	URL                    string  `json:"url"`
	ExternalURL            *string `json:"external_url"`
	Tags                   *string `json:"tags"`
	Enabled                int     `json:"enabled"`
	LibraryRefreshInterval int     `json:"library_refresh_interval"`
}

func newProfilarrClient(client *HTTPClient, cfg *ServiceConfig) *profilarrClient {
	return &profilarrClient{client: client, config: cfg}
}

func (p *profilarrClient) endpoint(path string) string {
	return strings.TrimRight(p.config.URL, "/") + path
}

func (p *profilarrClient) health(ctx context.Context) error {
	body, err := p.client.Get(ctx, p.endpoint("/api/v1/health"), nil)
	wipeCredentialBytes(body)
	return err
}

func (p *profilarrClient) instances(ctx context.Context) ([]profilarrInstance, error) {
	body, err := p.client.Get(ctx, p.endpoint("/api/v1/arr"), nil)
	if err != nil {
		return nil, err
	}
	defer wipeCredentialBytes(body)
	var instances []profilarrInstance
	if err := json.Unmarshal(body, &instances); err != nil {
		return nil, fmt.Errorf("decode Profilarr instances: %w", err)
	}
	return instances, nil
}

func (p *profilarrClient) validate(
	ctx context.Context,
	kind string,
	service *ServiceConfig,
) error {
	body, err := p.client.Post(
		ctx,
		p.endpoint("/arr/validate"),
		nil,
		map[string]string{
			"type":   kind,
			"url":    service.URL,
			"apiKey": service.APIKey,
		},
	)
	if err != nil {
		return err
	}
	defer wipeCredentialBytes(body)
	var result struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode Profilarr validation: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("Profilarr rejected Arr connection")
	}
	return nil
}

func (p *profilarrClient) storedConnectionWorks(
	ctx context.Context,
	id int,
) error {
	body, err := p.client.Get(
		ctx,
		p.endpoint("/arr/"+strconv.Itoa(id)+"/logs?page=1&pageSize=1"),
		nil,
	)
	wipeCredentialBytes(body)
	return err
}

func (p *profilarrClient) save(
	ctx context.Context,
	kind string,
	service *ServiceConfig,
	current *profilarrInstance,
) error {
	origin, err := url.Parse(p.config.URL)
	if err != nil || origin.Scheme != "http" || origin.Host == "" {
		return fmt.Errorf("parse Profilarr internal origin")
	}
	origin.Path, origin.RawPath, origin.RawQuery, origin.Fragment = "", "", "", ""
	headers := map[string]string{"Origin": origin.String()}
	values := make(url.Values)
	values.Set("name", strings.ToUpper(kind[:1])+kind[1:])
	values.Set("type", kind)
	values.Set("url", service.URL)
	values.Set("api_key", service.APIKey)
	values.Set("tags", "[]")
	values.Set("library_refresh_interval", "0")
	endpoint := p.endpoint("/arr/new")
	if current != nil {
		values.Set("name", current.Name)
		if current.ExternalURL != nil {
			values.Set("external_url", *current.ExternalURL)
		}
		if current.Tags != nil {
			values.Set("tags", *current.Tags)
		}
		values.Set(
			"library_refresh_interval",
			strconv.Itoa(current.LibraryRefreshInterval),
		)
		endpoint = p.endpoint(
			"/arr/" + strconv.Itoa(current.ID) + "/settings?/update",
		)
	}
	body, err := p.client.PostForm(ctx, endpoint, headers, values)
	wipeCredentialBytes(body)
	return err
}

func (i *Integrator) integrateProfilarr(ctx context.Context) []*IntegrationResult {
	client := newProfilarrClient(
		i.httpClient,
		serviceControlConfig(i.services["profilarr"]),
	)
	instances, err := client.instances(ctx)
	if err != nil {
		return []*IntegrationResult{{
			Service: "profilarr → sonarr/radarr",
			Message: "Failed to inspect Arr instances",
			Error:   err,
		}}
	}
	results := make([]*IntegrationResult, 0, 2)
	for _, kind := range []string{"radarr", "sonarr"} {
		service := i.services[kind]
		if service == nil || !service.Enabled {
			continue
		}
		result := &IntegrationResult{Service: "profilarr → " + kind}
		var current *profilarrInstance
		for index := range instances {
			if strings.EqualFold(instances[index].Type, kind) &&
				strings.EqualFold(instances[index].Name, strings.ToUpper(kind[:1])+kind[1:]) {
				current = &instances[index]
				break
			}
		}
		if err := client.validate(ctx, kind, service); err != nil {
			result.Message, result.Error = "Managed connection failed preflight", err
			results = append(results, result)
			continue
		}
		if current != nil && strings.TrimRight(current.URL, "/") == strings.TrimRight(service.URL, "/") &&
			current.Enabled == 1 && client.storedConnectionWorks(ctx, current.ID) == nil {
			result.Success, result.Message = true, "Already configured and verified"
			results = append(results, result)
			continue
		}
		if i.config.DryRun {
			result.Success, result.Message = true, "[DRY RUN] Would repair managed connection"
			results = append(results, result)
			continue
		}
		if err := client.save(ctx, kind, service, current); err != nil {
			result.Message, result.Error = "Failed to repair managed connection", err
			results = append(results, result)
			continue
		}
		updated, err := client.instances(ctx)
		if err != nil {
			result.Message, result.Error = "Failed to read repaired connection", err
			results = append(results, result)
			continue
		}
		var verified *profilarrInstance
		for index := range updated {
			if strings.EqualFold(updated[index].Type, kind) &&
				strings.EqualFold(updated[index].Name, strings.ToUpper(kind[:1])+kind[1:]) {
				verified = &updated[index]
				break
			}
		}
		if verified == nil || strings.TrimRight(verified.URL, "/") != strings.TrimRight(service.URL, "/") ||
			client.storedConnectionWorks(ctx, verified.ID) != nil {
			result.Message = "Repaired connection failed verification"
			result.Error = fmt.Errorf("Profilarr managed connection mismatch")
			results = append(results, result)
			continue
		}
		result.Success, result.Message = true, "Repaired and verified"
		results = append(results, result)
	}
	return results
}
