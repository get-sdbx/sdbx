package registry

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Cache manages caching of Git sources
type Cache struct {
	baseDir  string
	ttl      time.Duration
	metadata map[string]CacheMetadata
	mu       sync.RWMutex
	metaPath string
}

// CacheMetadata stores metadata about cached sources
type CacheMetadata struct {
	Name        string    `json:"name"`
	URL         string    `json:"url,omitempty"`
	Branch      string    `json:"branch,omitempty"`
	Commit      string    `json:"commit,omitempty"`
	LastUpdated time.Time `json:"last_updated"`
}

// NewCache creates a new Cache
func NewCache(baseDir string) *Cache {
	c := &Cache{
		baseDir:  baseDir,
		ttl:      24 * time.Hour,
		metadata: make(map[string]CacheMetadata),
		metaPath: filepath.Join(baseDir, "cache.json"),
	}

	// Catalogs are executable configuration. Keep cached definitions and
	// verification metadata private to the current user.
	_ = os.MkdirAll(baseDir, 0o700)

	// Load existing metadata
	c.loadMetadata()

	return c
}

// SetTTL sets the cache TTL
func (c *Cache) SetTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
}

// GetRepoPath returns the path where a repo should be cached
func (c *Cache) GetRepoPath(sourceName string) string {
	return filepath.Join(c.baseDir, cacheKey(sourceName))
}

// CreateStagingDir creates a private sibling directory for an untrusted fetch.
func (c *Cache) CreateStagingDir(sourceName string) (string, error) {
	if err := os.MkdirAll(c.baseDir, 0o700); err != nil {
		return "", fmt.Errorf("create source cache root: %w", err)
	}
	stagingPath, err := os.MkdirTemp(c.baseDir, "."+cacheKey(sourceName)+"-staging-")
	if err != nil {
		return "", fmt.Errorf("create source staging cache: %w", err)
	}
	// #nosec G302 -- directories require execute permission; 0700 is private
	// to the current user and is stricter than the flagged public-write modes.
	if err := os.Chmod(stagingPath, 0o700); err != nil {
		_ = os.RemoveAll(stagingPath)
		return "", fmt.Errorf("protect source staging cache: %w", err)
	}
	return stagingPath, nil
}

// ValidatePromotionBudget checks the persistent aggregate cache size after a
// staging checkout would replace the currently active source.
func (c *Cache) ValidatePromotionBudget(sourceName, stagingPath string) error {
	if err := c.validateManagedPath(stagingPath); err != nil {
		return err
	}

	if _, err := inspectSourceDirectory(stagingPath, sourceDirectoryLimits{
		maxBytes:            externalSourceCacheLimit,
		maxEntries:          externalSourceCacheEntryLimit,
		maxWorkingFileBytes: externalSourceWorkingFileLimit,
		rejectSymlinks:      true,
	}); err != nil {
		return fmt.Errorf("inspect source staging cache: %w", err)
	}

	totalUsage, err := inspectSourceDirectory(c.baseDir, sourceDirectoryLimits{
		maxBytes:   externalSourceGlobalCacheLimit + externalSourceCacheLimit,
		maxEntries: externalSourceCacheEntryLimit * 5,
	})
	if err != nil {
		return fmt.Errorf("inspect aggregate source cache: %w", err)
	}

	activePath := c.GetRepoPath(sourceName)
	activeUsage, err := inspectSourceDirectory(activePath, sourceDirectoryLimits{
		maxBytes:   externalSourceCacheLimit,
		maxEntries: externalSourceCacheEntryLimit,
	})
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect active source cache: %w", err)
	}

	persistentBytes := totalUsage.bytes - activeUsage.bytes
	if persistentBytes > externalSourceGlobalCacheLimit {
		return &sourceResourceError{
			resource: "aggregate external-source cache byte",
			limit:    externalSourceGlobalCacheLimit,
		}
	}
	return nil
}

// PromoteRepo atomically replaces one active source checkout. The previous
// verified checkout is restored if promotion fails.
func (c *Cache) PromoteRepo(sourceName, stagingPath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.validateManagedPath(stagingPath); err != nil {
		return err
	}
	if err := c.ValidatePromotionBudget(sourceName, stagingPath); err != nil {
		return err
	}

	activePath := c.GetRepoPath(sourceName)
	stagingInfo, err := os.Lstat(stagingPath)
	if err != nil {
		return fmt.Errorf("inspect source staging cache: %w", err)
	}
	if !stagingInfo.IsDir() || stagingInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("source staging cache is not a real directory")
	}

	backupPath, err := os.MkdirTemp(c.baseDir, "."+cacheKey(sourceName)+"-previous-")
	if err != nil {
		return fmt.Errorf("reserve source cache rollback path: %w", err)
	}
	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("prepare source cache rollback path: %w", err)
	}
	backupPresent := false
	defer func() {
		if backupPresent {
			_ = os.RemoveAll(backupPath)
		}
	}()

	if activeInfo, statErr := os.Lstat(activePath); statErr == nil {
		if activeInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("active source cache must not be a symbolic link")
		}
		if err := os.Rename(activePath, backupPath); err != nil {
			return fmt.Errorf("stage active source cache for rollback: %w", err)
		}
		backupPresent = true
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect active source cache: %w", statErr)
	}

	if err := os.Rename(stagingPath, activePath); err != nil {
		if backupPresent {
			if rollbackErr := os.Rename(backupPath, activePath); rollbackErr != nil {
				return fmt.Errorf(
					"promote source cache: %w (rollback also failed: %v)",
					err,
					rollbackErr,
				)
			}
			backupPresent = false
		}
		return fmt.Errorf("promote source cache: %w", err)
	}

	if backupPresent {
		if err := os.RemoveAll(backupPath); err == nil {
			backupPresent = false
		}
	}
	return nil
}

func (c *Cache) validateManagedPath(path string) error {
	absoluteBase, err := filepath.Abs(c.baseDir)
	if err != nil {
		return fmt.Errorf("resolve source cache root: %w", err)
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve source cache path: %w", err)
	}
	relativePath, err := filepath.Rel(absoluteBase, absolutePath)
	if err != nil {
		return fmt.Errorf("validate source cache path: %w", err)
	}
	if relativePath == "." || relativePath == ".." ||
		strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) ||
		filepath.Dir(relativePath) != "." {
		return fmt.Errorf("source cache path must be a direct child of the cache root")
	}
	return nil
}

func cacheKey(sourceName string) string {
	key := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, sourceName)
	key = strings.Trim(key, ".-")
	if key == "" {
		key = "source"
	}
	sum := sha256.Sum256([]byte(sourceName))
	return fmt.Sprintf("%s-%x", key, sum[:4])
}

// NeedsUpdate checks if a source needs to be updated
func (c *Cache) NeedsUpdate(sourceName string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	meta, exists := c.metadata[sourceName]
	if !exists {
		return true
	}

	return time.Since(meta.LastUpdated) > c.ttl
}

// MarkUpdated marks a source as updated
func (c *Cache) MarkUpdated(sourceName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	meta := c.metadata[sourceName]
	meta.Name = sourceName
	meta.LastUpdated = time.Now()
	c.metadata[sourceName] = meta

	c.saveMetadata()
}

// SetCommit stores the commit hash for a source
func (c *Cache) SetCommit(sourceName, commit string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	meta := c.metadata[sourceName]
	meta.Commit = commit
	c.metadata[sourceName] = meta

	c.saveMetadata()
}

// GetCommit returns the cached commit hash for a source
func (c *Cache) GetCommit(sourceName string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.metadata[sourceName].Commit
}

// GetLastUpdated returns when a source was last updated
func (c *Cache) GetLastUpdated(sourceName string) time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.metadata[sourceName].LastUpdated
}

// GetMetadata returns all cache metadata
func (c *Cache) GetMetadata() map[string]CacheMetadata {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy
	result := make(map[string]CacheMetadata)
	for k, v := range c.metadata {
		result[k] = v
	}
	return result
}

// Clear clears the cache for a specific source
func (c *Cache) Clear(sourceName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove from metadata
	delete(c.metadata, sourceName)
	c.saveMetadata()

	// Remove cached files
	repoPath := c.GetRepoPath(sourceName)
	return os.RemoveAll(repoPath)
}

// ClearAll clears all cached sources
func (c *Cache) ClearAll() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.metadata = make(map[string]CacheMetadata)
	c.saveMetadata()

	// Remove all files except metadata
	entries, err := os.ReadDir(c.baseDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.Name() == "cache.json" {
			continue
		}
		path := filepath.Join(c.baseDir, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}

	return nil
}

// GetSize returns the total size of the cache in bytes
func (c *Cache) GetSize() (int64, error) {
	var size int64

	err := filepath.WalkDir(c.baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			size += info.Size()
		}
		return nil
	})

	return size, err
}

// loadMetadata loads cache metadata from disk
func (c *Cache) loadMetadata() {
	data, err := os.ReadFile(c.metaPath)
	if err != nil {
		return
	}

	var metadata map[string]CacheMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return
	}

	c.metadata = metadata
}

// saveMetadata saves cache metadata to disk
func (c *Cache) saveMetadata() {
	data, err := json.MarshalIndent(c.metadata, "", "  ")
	if err != nil {
		return
	}

	_ = os.WriteFile(c.metaPath, data, 0o600)
}

// Exists checks if a source is cached
func (c *Cache) Exists(sourceName string) bool {
	repoPath := c.GetRepoPath(sourceName)
	_, err := os.Stat(repoPath)
	return err == nil
}

// IsCached checks if a source is cached and not expired
func (c *Cache) IsCached(sourceName string) bool {
	if !c.Exists(sourceName) {
		return false
	}
	return !c.NeedsUpdate(sourceName)
}

// ForceExpire forces a source to be marked as needing update
func (c *Cache) ForceExpire(sourceName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	meta := c.metadata[sourceName]
	meta.LastUpdated = time.Time{} // Zero time
	c.metadata[sourceName] = meta

	c.saveMetadata()
}

// GetCachedSources returns names of all cached sources
func (c *Cache) GetCachedSources() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var names []string
	for name := range c.metadata {
		names = append(names, name)
	}
	return names
}
