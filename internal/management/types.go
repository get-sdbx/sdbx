// Package management defines the typed, project-scoped management boundary
// shared by the local operator, broker transport, and web console.
package management

import (
	"context"
	"time"

	"github.com/get-sdbx/sdbx/internal/addons"
	"github.com/get-sdbx/sdbx/internal/settings"
)

// Operator exposes only bounded SDBX operations. It intentionally has no
// arbitrary command, path, mount, Docker API, or container-exec primitive.
type Operator interface {
	Preview(context.Context, ImpactRequest) (*Impact, error)
	Summary(context.Context) (*Summary, error)
	Security(context.Context) (*SecurityReport, error)
	Diagnostics(context.Context) (*DiagnosticsReport, error)
	Services(context.Context) ([]Service, error)
	Logs(context.Context, LogsRequest) (*LogsResult, error)
	Addons(context.Context) ([]Addon, error)
	SetAddon(context.Context, AddonRequest) (*addons.Result, error)
	Settings(context.Context) (*Settings, error)
	SetSetting(context.Context, SettingRequest) (*settings.Result, error)
	Backups(context.Context) ([]Backup, error)
	CreateBackup(context.Context, CreateBackupRequest) (*Backup, error)
	RestoreBackup(context.Context, RestoreBackupRequest) error
	DeleteBackup(context.Context, DeleteBackupRequest) error
	Stack(context.Context, StackRequest) error
}

type ImpactRequest struct {
	Operation string `json:"operation"`
	Target    string `json:"target,omitempty"`
}

type Impact struct {
	Operation    string   `json:"operation"`
	Title        string   `json:"title"`
	Consequences []string `json:"consequences"`
	Confirmation string   `json:"confirmation"`
	HighImpact   bool     `json:"highImpact"`
}

type SecurityReport struct {
	ProjectVerified        bool           `json:"projectVerified"`
	GeneratedFilesVerified bool           `json:"generatedFilesVerified"`
	LockSchema             int            `json:"lockSchema"`
	LockedServices         int            `json:"lockedServices"`
	ImmutableImages        int            `json:"immutableImages"`
	ExposureMode           string         `json:"exposureMode"`
	TLSProvider            string         `json:"tlsProvider"`
	HTTPSRequired          bool           `json:"httpsRequired"`
	RoutingStrategy        string         `json:"routingStrategy"`
	VPNEnabled             bool           `json:"vpnEnabled"`
	DownloadVPNEnforced    bool           `json:"downloadVpnEnforced"`
	RouteAuth              map[string]int `json:"routeAuth"`
}

type DiagnosticsReport struct {
	Healthy bool               `json:"healthy"`
	Summary DiagnosticsSummary `json:"summary"`
	Checks  []DiagnosticCheck  `json:"checks"`
}

type DiagnosticsSummary struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

type DiagnosticCheck struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	DurationMS int64  `json:"durationMs"`
}

type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	RequestID string    `json:"requestId"`
	Actor     string    `json:"actor"`
	Groups    []string  `json:"groups,omitempty"`
	Operation string    `json:"operation"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Outcome   string    `json:"outcome"`
	Status    int       `json:"status,omitempty"`
}

type Warning struct {
	Service string `json:"service"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

type Summary struct {
	Domain           string    `json:"domain"`
	ProjectID        string    `json:"projectId"`
	RunningServices  int       `json:"runningServices"`
	TotalServices    int       `json:"totalServices"`
	EnabledAddons    int       `json:"enabledAddons"`
	TotalAddons      int       `json:"totalAddons"`
	Backups          int       `json:"backups"`
	RegistryWarnings int       `json:"registryWarnings"`
	Warnings         []Warning `json:"warnings"`
}

type Service struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Category    string           `json:"category"`
	Route       string           `json:"route,omitempty"`
	RouteAuth   string           `json:"routeAuth,omitempty"`
	Launcher    *ServiceLauncher `json:"launcher,omitempty"`
	Status      string           `json:"status"`
	Health      string           `json:"health,omitempty"`
	Image       string           `json:"image,omitempty"`
	Ports       string           `json:"ports,omitempty"`
	Running     bool             `json:"running"`
	Present     bool             `json:"present"`
	ExitCode    int              `json:"exit_code,omitempty"`
	Definition  string           `json:"definitionVersion"`
}

type ServiceLauncher struct {
	Enabled  bool   `json:"enabled"`
	Group    string `json:"group"`
	Icon     string `json:"icon,omitempty"`
	Subtitle string `json:"subtitle,omitempty"`
}

type LogsRequest struct {
	Service string `json:"service"`
	Tail    int    `json:"tail"`
}

type LogsResult struct {
	Service string `json:"service,omitempty"`
	Logs    string `json:"logs"`
}

type Addon struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Source      string `json:"source"`
	Enabled     bool   `json:"enabled"`
}

type AddonRequest struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Confirm string `json:"confirm"`
}

type Settings struct {
	Values    map[string]any   `json:"settings"`
	Fields    []settings.Field `json:"fields"`
	ValidKeys []string         `json:"validKeys"`
}

type SettingRequest struct {
	Key                         string `json:"key"`
	Value                       string `json:"value"`
	ConfirmUnprotectedDownloads bool   `json:"confirm_unprotected_downloads"`
	Confirm                     string `json:"confirm"`
}

type Backup struct {
	Name      string    `json:"name"`
	Timestamp time.Time `json:"timestamp"`
	Size      int64     `json:"size"`
}

type CreateBackupRequest struct {
	Recipient  string `json:"recipient,omitempty"`
	Passphrase []byte `json:"-"`
}

type RestoreBackupRequest struct {
	Name                 string `json:"name"`
	Passphrase           []byte `json:"-"`
	Confirm              string `json:"confirm"`
	RelocateManagedRoots bool   `json:"relocate_managed_roots,omitempty"`
}

type DeleteBackupRequest struct {
	Name    string `json:"name"`
	Confirm string `json:"confirm"`
}

type StackRequest struct {
	Action  string `json:"action"`
	Confirm string `json:"confirm"`
}
