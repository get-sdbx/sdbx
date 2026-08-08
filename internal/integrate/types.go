package integrate

import (
	"encoding/json"
	"time"

	sdbxconfig "github.com/get-sdbx/sdbx/internal/config"
	"github.com/get-sdbx/sdbx/internal/registry"
)

// ServiceConfig represents a service configuration for integration
type ServiceConfig struct {
	Name       string
	URL        string // Stable service-to-service Docker URL
	ControlURL string // Optional host-reachable URL for API control calls
	APIKey     string
	Enabled    bool
}

// IntegrationResult represents the result of an integration attempt
type IntegrationResult struct {
	Service string
	Success bool
	Message string
	Error   error
}

// Config holds configuration for the integrator
type Config struct {
	Services      map[string]*ServiceConfig
	ProjectConfig *sdbxconfig.Config
	// Graph is the verified resolution graph used by generation and routing.
	// Managed integrations derive internal URLs from it instead of rebuilding
	// routing paths independently.
	Graph         *registry.ResolutionGraph
	Timeout       time.Duration
	RetryAttempts int
	RetryDelay    time.Duration
	DryRun        bool
	Verbose       bool
	// RotateCredentials requests an explicit, transactional replacement of
	// supported SDBX-managed native credentials during reconciliation.
	RotateCredentials bool
	// InCluster, when true, signals that this integrator process is already
	// running inside both SDBX application and download networks so the HTTP
	// integrators can use Docker DNS service names directly.
	InCluster bool
}

// DefaultConfig returns default integration configuration
func DefaultConfig() *Config {
	return &Config{
		Services:      make(map[string]*ServiceConfig),
		Timeout:       30 * time.Second,
		RetryAttempts: 3,
		RetryDelay:    5 * time.Second,
		DryRun:        false,
		Verbose:       false,
	}
}

// QBittorrentConfig represents qBittorrent configuration
type QBittorrentConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ProwlarrApplication represents an *arr app in Prowlarr
type ProwlarrApplication struct {
	ID             int             `json:"id,omitempty"`
	Name           string          `json:"name"`
	Enable         bool            `json:"enable"`
	SyncLevel      string          `json:"syncLevel"` // disabled, addOnly, fullSync
	Implementation string          `json:"implementation"`
	ConfigContract string          `json:"configContract"`
	Tags           []int           `json:"tags"`
	Fields         []ProwlarrField `json:"fields"`
}

// ProwlarrField represents a configuration field
type ProwlarrField struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}

// DownloadClient represents a download client configuration for *arr apps
type DownloadClient struct {
	ID                       int                   `json:"id,omitempty"`
	Name                     string                `json:"name"`
	Implementation           string                `json:"implementation"`
	ImplementationName       string                `json:"implementationName,omitempty"`
	ConfigContract           string                `json:"configContract"`
	InfoLink                 string                `json:"infoLink,omitempty"`
	Protocol                 string                `json:"protocol"` // torrent or usenet
	Priority                 int                   `json:"priority"`
	Enable                   bool                  `json:"enable"`
	RemoveCompletedDownloads bool                  `json:"removeCompletedDownloads"`
	RemoveFailedDownloads    bool                  `json:"removeFailedDownloads"`
	Tags                     []int                 `json:"tags"`
	Fields                   []DownloadClientField `json:"fields"`
}

// DownloadClientField represents a download client field
type DownloadClientField struct {
	Name          string          `json:"name"`
	Label         string          `json:"label,omitempty"`
	HelpText      string          `json:"helpText,omitempty"`
	Value         interface{}     `json:"value"`
	Type          string          `json:"type,omitempty"`
	Advanced      bool            `json:"advanced,omitempty"`
	Order         int             `json:"order,omitempty"`
	Privacy       string          `json:"privacy,omitempty"`
	IsFloat       bool            `json:"isFloat,omitempty"`
	SelectOptions json.RawMessage `json:"selectOptions,omitempty"`
}
