// Package services exposes the canonical SDBX service catalog to the registry.
//
// Keeping the embed directive beside the public catalog avoids maintaining a
// second copied catalog under internal/registry.
package services

import "embed"

// Catalog contains every official service definition shipped with this SDBX
// build. Third-party sources are loaded separately and never modify this
// filesystem.
//
//go:embed core/*/service.yaml addons/*/service.yaml images.lock.json
var Catalog embed.FS

// ImageLock is the reviewed immutable OCI snapshot used for official
// first-run locks. Explicit update commands may refresh beyond this snapshot.
//
//go:embed images.lock.json
var ImageLock []byte
