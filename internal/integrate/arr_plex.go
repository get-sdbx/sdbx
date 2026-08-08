package integrate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const managedPlexNotificationName = "SDBX Plex"

func (a *ArrClient) getNotifications(ctx context.Context) ([]map[string]any, error) {
	endpoint := fmt.Sprintf("%s/api/%s/notification", a.config.URL, a.version())
	body, err := a.client.Get(ctx, endpoint, map[string]string{"X-Api-Key": a.config.APIKey})
	if err != nil {
		return nil, fmt.Errorf("get notifications: %w", err)
	}
	defer wipeCredentialBytes(body)
	var notifications []map[string]any
	if err := json.Unmarshal(body, &notifications); err != nil {
		return nil, fmt.Errorf("decode notifications: %w", err)
	}
	return notifications, nil
}

func (a *ArrClient) getNotificationSchemas(ctx context.Context) ([]map[string]any, error) {
	endpoint := fmt.Sprintf("%s/api/%s/notification/schema", a.config.URL, a.version())
	body, err := a.client.Get(ctx, endpoint, map[string]string{"X-Api-Key": a.config.APIKey})
	if err != nil {
		return nil, fmt.Errorf("get notification schemas: %w", err)
	}
	defer wipeCredentialBytes(body)
	var schemas []map[string]any
	if err := json.Unmarshal(body, &schemas); err != nil {
		return nil, fmt.Errorf("decode notification schemas: %w", err)
	}
	return schemas, nil
}

func (a *ArrClient) testNotification(ctx context.Context, notification map[string]any) error {
	endpoint := fmt.Sprintf("%s/api/%s/notification/test", a.config.URL, a.version())
	body, err := a.client.Post(ctx, endpoint, map[string]string{"X-Api-Key": a.config.APIKey}, notification)
	wipeCredentialBytes(body)
	if err != nil {
		return fmt.Errorf("test notification: %w", err)
	}
	return nil
}

func (a *ArrClient) saveNotification(
	ctx context.Context,
	notification map[string]any,
	update bool,
) error {
	endpoint := fmt.Sprintf("%s/api/%s/notification", a.config.URL, a.version())
	var body []byte
	var err error
	if update {
		id, ok := notificationInteger(notification["id"])
		if !ok || id <= 0 {
			return fmt.Errorf("managed notification has no stable identifier")
		}
		body, err = a.client.Put(
			ctx,
			fmt.Sprintf("%s/%d", endpoint, id),
			map[string]string{"X-Api-Key": a.config.APIKey},
			notification,
		)
	} else {
		body, err = a.client.Post(
			ctx,
			endpoint,
			map[string]string{"X-Api-Key": a.config.APIKey},
			notification,
		)
	}
	wipeCredentialBytes(body)
	if err != nil {
		return fmt.Errorf("save notification: %w", err)
	}
	return nil
}

func notificationInteger(value any) (int, bool) {
	switch candidate := value.(type) {
	case float64:
		return int(candidate), candidate == float64(int(candidate))
	case int:
		return candidate, true
	default:
		return 0, false
	}
}

func notificationField(notification map[string]any, name string) (any, bool) {
	fields, ok := notification["fields"].([]any)
	if !ok {
		return nil, false
	}
	for _, candidate := range fields {
		field, ok := candidate.(map[string]any)
		if !ok || field["name"] != name {
			continue
		}
		return field["value"], true
	}
	return nil, false
}

func setNotificationField(notification map[string]any, name string, value any) bool {
	fields, ok := notification["fields"].([]any)
	if !ok {
		return false
	}
	for _, candidate := range fields {
		field, ok := candidate.(map[string]any)
		if !ok || field["name"] != name {
			continue
		}
		field["value"] = value
		return true
	}
	return false
}

func configureManagedPlexNotification(
	notification map[string]any,
	arrName, token string,
) error {
	notification["name"] = managedPlexNotificationName
	notification["implementation"] = "PlexServer"
	notification["configContract"] = "PlexServerSettings"
	notification["onUpgrade"] = true
	notification["onRename"] = true
	if arrName == "lidarr" {
		notification["onReleaseImport"] = true
	} else {
		notification["onDownload"] = true
	}
	for name, value := range map[string]any{
		"host":          "sdbx-plex",
		"port":          32400,
		"useSsl":        false,
		"urlBase":       "",
		"authToken":     token,
		"updateLibrary": true,
	} {
		if !setNotificationField(notification, name, value) {
			return fmt.Errorf("Plex notification schema has no %s field", name)
		}
	}
	if _, exists := notificationField(notification, "server"); exists {
		setNotificationField(notification, "server", "http://sdbx-plex:32400")
	}
	return nil
}

func managedPlexNotificationMatches(notification map[string]any, arrName string) bool {
	if !strings.EqualFold(fmt.Sprint(notification["name"]), managedPlexNotificationName) ||
		!strings.EqualFold(fmt.Sprint(notification["implementation"]), "PlexServer") ||
		notification["onUpgrade"] != true || notification["onRename"] != true {
		return false
	}
	if arrName == "lidarr" {
		if notification["onReleaseImport"] != true {
			return false
		}
	} else if notification["onDownload"] != true {
		return false
	}
	expected := map[string]any{
		"host":          "sdbx-plex",
		"port":          32400,
		"useSsl":        false,
		"urlBase":       "",
		"updateLibrary": true,
	}
	for name, value := range expected {
		actual, ok := notificationField(notification, name)
		if !ok || (name == "urlBase" && actual != nil && fmt.Sprint(actual) != "") ||
			(name != "urlBase" && fmt.Sprint(actual) != fmt.Sprint(value)) {
			return false
		}
	}
	if server, exists := notificationField(notification, "server"); exists &&
		fmt.Sprint(server) != "http://sdbx-plex:32400" {
		return false
	}
	return true
}

func findManagedPlexNotification(notifications []map[string]any) map[string]any {
	for _, notification := range notifications {
		if strings.EqualFold(fmt.Sprint(notification["name"]), managedPlexNotificationName) &&
			strings.EqualFold(fmt.Sprint(notification["implementation"]), "PlexServer") {
			return notification
		}
	}
	for _, notification := range notifications {
		if strings.EqualFold(fmt.Sprint(notification["name"]), "Plex Media Server") &&
			strings.EqualFold(fmt.Sprint(notification["implementation"]), "PlexServer") {
			return notification
		}
	}
	return nil
}

func findPlexNotificationSchema(schemas []map[string]any) map[string]any {
	for _, schema := range schemas {
		if strings.EqualFold(fmt.Sprint(schema["implementation"]), "PlexServer") {
			return schema
		}
	}
	return nil
}

func (i *Integrator) integrateArrPlexNotifications(ctx context.Context) []*IntegrationResult {
	plex := i.services["plex"]
	if plex == nil || !plex.Enabled {
		return nil
	}
	results := make([]*IntegrationResult, 0, 4)
	for _, name := range []string{"radarr", "sonarr", "lidarr", "whisparr"} {
		service := i.services[name]
		if service == nil || !service.Enabled {
			continue
		}
		result := &IntegrationResult{Service: name + " → plex library refresh"}
		arr := NewArrClient(i.httpClient, serviceControlConfig(service))
		notifications, err := arr.getNotifications(ctx)
		if err != nil {
			result.Message, result.Error = "Failed to inspect Plex notifications", err
			results = append(results, result)
			continue
		}
		managed := findManagedPlexNotification(notifications)
		if managed != nil && managedPlexNotificationMatches(managed, name) &&
			arr.testNotification(ctx, managed) == nil {
			result.Success, result.Message = true, "Managed Plex refresh already configured and verified"
			results = append(results, result)
			continue
		}
		update := managed != nil
		if managed == nil {
			schemas, schemaErr := arr.getNotificationSchemas(ctx)
			if schemaErr != nil {
				result.Message, result.Error = "Failed to inspect Plex notification schema", schemaErr
				results = append(results, result)
				continue
			}
			managed = findPlexNotificationSchema(schemas)
			if managed == nil {
				result.Message = "Plex notification schema is unavailable"
				result.Error = fmt.Errorf("%s exposes no PlexServer notification", name)
				results = append(results, result)
				continue
			}
		}
		if err := configureManagedPlexNotification(managed, name, plex.APIKey); err != nil {
			result.Message, result.Error = "Failed to build managed Plex notification", err
			results = append(results, result)
			continue
		}
		if i.config.DryRun {
			result.Success, result.Message = true, "[DRY RUN] Would repair and verify Plex library refresh"
			results = append(results, result)
			continue
		}
		if err := arr.testNotification(ctx, managed); err != nil {
			result.Message, result.Error = "Managed Plex notification failed preflight", err
			results = append(results, result)
			continue
		}
		if err := arr.saveNotification(ctx, managed, update); err != nil {
			result.Message, result.Error = "Failed to persist managed Plex notification", err
			results = append(results, result)
			continue
		}
		notifications, err = arr.getNotifications(ctx)
		if err != nil {
			result.Message, result.Error = "Failed to verify managed Plex notification", err
			results = append(results, result)
			continue
		}
		managed = findManagedPlexNotification(notifications)
		if managed == nil || !managedPlexNotificationMatches(managed, name) ||
			arr.testNotification(ctx, managed) != nil {
			result.Message = "Managed Plex notification failed read-back verification"
			result.Error = fmt.Errorf("%s Plex refresh is not usable", name)
			results = append(results, result)
			continue
		}
		result.Success, result.Message = true, "Repaired and verified Plex library refresh"
		results = append(results, result)
	}
	return results
}
