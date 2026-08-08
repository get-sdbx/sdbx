// Package securefs provides permission-explicit filesystem helpers for
// SDBX-managed state.
package securefs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ReadRegularFile reads at most maxBytes from a regular file without
// accepting symlinks, directories, devices, sockets, or other special files.
func ReadRegularFile(path string, maxBytes int64) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("read path is empty")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("maximum read size must be positive")
	}

	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a symlink or special file", path)
	}
	if before.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds the %d-byte read limit", path, maxBytes)
	}

	// #nosec G304 -- Lstat, regular-file checks, and SameFile pin this open to
	// the inspected inode before any bytes are accepted.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open file %s: %w", path, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%s changed while it was being opened", path)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds the %d-byte read limit", path, maxBytes)
	}
	return data, nil
}

// ReadRegularFileAt reads a relative file through a verified, pinned directory
// root. The root itself and the final file must be real inodes; os.Root keeps a
// later ancestor rename or symlink swap from redirecting the open elsewhere.
func ReadRegularFileAt(rootPath, name string, maxBytes int64) ([]byte, error) {
	if rootPath == "" {
		return nil, fmt.Errorf("read root is empty")
	}
	if name == "" || filepath.IsAbs(name) {
		return nil, fmt.Errorf("root-relative read path is invalid")
	}
	cleanedName := filepath.Clean(name)
	if cleanedName == "." || cleanedName == ".." ||
		strings.HasPrefix(cleanedName, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("root-relative read path escapes its root")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("maximum read size must be positive")
	}

	root, _, err := OpenVerifiedRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	before, err := root.Lstat(cleanedName)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"%s must be a regular file, not a symlink or special file",
			cleanedName,
		)
	}
	if before.Size() > maxBytes {
		return nil, fmt.Errorf(
			"%s exceeds the %d-byte read limit",
			cleanedName,
			maxBytes,
		)
	}
	file, err := root.Open(cleanedName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%s changed while it was being opened", cleanedName)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", cleanedName, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf(
			"%s exceeds the %d-byte read limit",
			cleanedName,
			maxBytes,
		)
	}
	return data, nil
}

// OpenVerifiedRoot opens and pins a real directory after rejecting a final
// symlink. The SameFile check prevents a path replacement between inspection
// and open from silently redirecting later root-scoped operations.
func OpenVerifiedRoot(rootPath string) (*os.Root, fs.FileInfo, error) {
	if rootPath == "" {
		return nil, nil, fmt.Errorf("root path is empty")
	}
	before, err := os.Lstat(rootPath)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, nil, fmt.Errorf("%s must be a real directory", rootPath)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open root %s: %w", rootPath, err)
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		_ = root.Close()
		return nil, nil, fmt.Errorf("%s changed while it was being opened", rootPath)
	}
	return root, opened, nil
}

// RejectSymlinkTraversal verifies every path component from trustedRoot
// through target. Components before trustedRoot are deliberately outside this
// trust decision, which permits platform-owned aliases such as macOS /var
// while rejecting redirects inside an SDBX project.
func RejectSymlinkTraversal(trustedRoot, target string) error {
	if trustedRoot == "" || target == "" {
		return fmt.Errorf("trusted root and target are required")
	}
	root := filepath.Clean(trustedRoot)
	target = filepath.Clean(target)
	rootInfo, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		// Nothing below a missing trusted root can exist yet. The caller owns
		// creation and the root's ancestors are outside this trust decision.
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect trusted root %s: %w", root, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return fmt.Errorf("trusted root %s must be a real directory", root)
	}
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	if relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(relative) {
		return fmt.Errorf("%s escapes trusted root %s", target, root)
	}
	current := root
	for _, component := range strings.Split(
		relative,
		string(filepath.Separator),
	) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s traverses symlink %s", target, current)
		}
		if !info.IsDir() && current != target {
			return fmt.Errorf("%s traverses non-directory %s", target, current)
		}
	}
	return nil
}

// EnsureDir creates path when needed, rejects symlink and non-directory
// components throughout the path, inherits the nearest existing directory's
// ownership when running as root, and repairs the final directory's mode.
func EnsureDir(path string, mode fs.FileMode) error {
	return ensureDir(path, mode, nil)
}

func ensureDir(
	path string,
	mode fs.FileMode,
	beforeFinalMetadata func(),
) error {
	if path == "" {
		return fmt.Errorf("directory path is empty")
	}
	if mode.Perm() != mode {
		return fmt.Errorf("directory mode must contain permission bits only")
	}
	cleaned, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolve directory path %s: %w", path, err)
	}
	if filepath.Dir(cleaned) == cleaned {
		return fmt.Errorf("refusing to change filesystem root mode")
	}

	current := cleaned
	for {
		info, err := os.Lstat(current)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("directory %s must not contain symlink component %s", path, current)
			}
			if !info.IsDir() {
				return fmt.Errorf("directory %s has non-directory component %s", path, current)
			}
			goto pin
		case errors.Is(err, os.ErrNotExist):
			parent := filepath.Dir(current)
			if parent == current {
				return fmt.Errorf("directory %s has no existing parent", path)
			}
			current = parent
		default:
			return fmt.Errorf("inspect directory component %s: %w", current, err)
		}
	}

pin:
	root, _, err := OpenVerifiedRoot(current)
	if err != nil {
		return fmt.Errorf("pin existing directory component %s: %w", current, err)
	}
	defer root.Close()

	relative, err := filepath.Rel(current, cleaned)
	if err != nil {
		return fmt.Errorf("resolve directory path below %s: %w", current, err)
	}
	target, err := openPinnedRootDirectoryAt(root, relative, true, mode)
	if err != nil {
		return fmt.Errorf("create and pin directory %s: %w", cleaned, err)
	}
	defer target.Close()

	if beforeFinalMetadata != nil {
		beforeFinalMetadata()
	}
	directory, err := target.Open(".")
	if err != nil {
		return fmt.Errorf("open pinned directory %s: %w", cleaned, err)
	}
	defer directory.Close()
	pinnedInfo, err := directory.Stat()
	if err != nil || !pinnedInfo.IsDir() {
		return fmt.Errorf("pinned directory %s is not a directory", cleaned)
	}
	if err := directory.Chmod(mode); err != nil {
		return fmt.Errorf("set directory mode for %s: %w", cleaned, err)
	}
	currentInfo, err := os.Lstat(cleaned)
	if err != nil ||
		currentInfo.Mode()&os.ModeSymlink != 0 ||
		!currentInfo.IsDir() ||
		!os.SameFile(pinnedInfo, currentInfo) {
		return fmt.Errorf("directory %s changed while metadata was applied", cleaned)
	}
	return nil
}

// WriteFileAtomic replaces path only after the complete new content has been
// written and synced. The temporary file is created beside the target so the
// final rename stays on one filesystem.
func WriteFileAtomic(
	path string,
	data []byte,
	dirMode fs.FileMode,
	fileMode fs.FileMode,
) (err error) {
	return WriteReaderAtomic(
		path,
		bytes.NewReader(data),
		int64(len(data)),
		dirMode,
		fileMode,
	)
}

// WriteFileAtomicAt replaces one base-name regular file through a pinned
// directory. Existing symlinks and special files are rejected rather than
// followed or silently replaced.
func WriteFileAtomicAt(
	rootPath string,
	name string,
	data []byte,
	fileMode fs.FileMode,
) (err error) {
	if fileMode.Perm() != fileMode {
		return fmt.Errorf("atomic file mode must contain permission bits only")
	}
	if name == "" || name == "." || filepath.Base(name) != name || !filepath.IsLocal(name) {
		return fmt.Errorf("atomic target must be a base filename")
	}
	root, rootInfo, err := OpenVerifiedRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	reference := rootInfo
	if targetInfo, statErr := root.Lstat(name); statErr == nil {
		if targetInfo.Mode()&os.ModeSymlink != 0 || !targetInfo.Mode().IsRegular() {
			return fmt.Errorf("atomic target %s must be a real regular file", name)
		}
		reference = targetInfo
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	temp, tempName, err := createRootTemporaryFile(root, name)
	if err != nil {
		return err
	}
	defer func() {
		_ = temp.Close()
		if tempName != "" {
			_ = root.Remove(tempName)
		}
	}()
	if err := InheritFileOwnership(temp, reference); err != nil {
		return err
	}
	if err := temp.Chmod(fileMode.Perm()); err != nil {
		return err
	}
	written, err := temp.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := root.Rename(tempName, name); err != nil {
		return err
	}
	tempName = ""
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// WriteReaderAtomic replaces path from a bounded stream only after the exact
// expected number of bytes has been written and synced.
func WriteReaderAtomic(
	path string,
	source io.Reader,
	expectedSize int64,
	dirMode fs.FileMode,
	fileMode fs.FileMode,
) (err error) {
	if path == "" {
		return fmt.Errorf("atomic write path is empty")
	}
	if source == nil {
		return fmt.Errorf("atomic write source is nil")
	}
	if expectedSize < 0 {
		return fmt.Errorf("atomic write size must not be negative")
	}
	if dirMode.Perm() != dirMode || fileMode.Perm() != fileMode {
		return fmt.Errorf("atomic write modes must contain permission bits only")
	}

	dir := filepath.Dir(path)
	if err := EnsureDir(dir, dirMode); err != nil {
		return fmt.Errorf("prepare parent directory %s: %w", dir, err)
	}

	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	tempPath := temp.Name()
	defer func() {
		if temp != nil {
			_ = temp.Close()
		}
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()

	if err = ApplyReplacementOwnership(temp, path); err != nil {
		return err
	}
	if err = temp.Chmod(fileMode); err != nil {
		return fmt.Errorf("set temporary file mode for %s: %w", path, err)
	}
	written, writeErr := io.Copy(
		temp,
		io.LimitReader(source, expectedSize+1),
	)
	if writeErr != nil {
		return fmt.Errorf("write temporary file for %s: %w", path, writeErr)
	}
	if written != expectedSize {
		return fmt.Errorf(
			"write temporary file for %s: wrote %d bytes, expected %d",
			path,
			written,
			expectedSize,
		)
	}
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary file for %s: %w", path, err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("close temporary file for %s: %w", path, err)
	}
	temp = nil

	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace %s atomically: %w", path, err)
	}

	// #nosec G304 -- dir is the already-validated parent of the exact atomic
	// replacement target and is opened only for an fsync.
	parent, openErr := os.Open(dir)
	if openErr != nil {
		return fmt.Errorf("open parent directory %s for sync: %w", dir, openErr)
	}
	defer parent.Close()
	if err = parent.Sync(); err != nil {
		return fmt.Errorf("sync parent directory %s: %w", dir, err)
	}
	return nil
}

// ApplyReplacementOwnership gives an already-open temporary file the
// ownership its final target should have. An existing regular target keeps its
// owner; a new target inherits the owner of its real parent directory. The
// operation is intentionally a no-op for non-root processes.
func ApplyReplacementOwnership(file *os.File, targetPath string) error {
	if file == nil {
		return fmt.Errorf("replacement file is nil")
	}
	if targetPath == "" {
		return fmt.Errorf("replacement target path is empty")
	}
	parent := filepath.Dir(targetPath)
	ownership, err := ownershipForReplacement(targetPath, parent)
	if err != nil {
		return fmt.Errorf("resolve ownership for %s: %w", targetPath, err)
	}
	if err := applyFileOwnership(file, ownership); err != nil {
		return fmt.Errorf("preserve ownership for %s: %w", targetPath, err)
	}
	return nil
}

// InheritFileOwnership gives an already-open file the ownership recorded on a
// trusted reference inode. It is a no-op for non-root processes and platforms
// where numeric ownership is unavailable.
func InheritFileOwnership(file *os.File, reference fs.FileInfo) error {
	if file == nil {
		return fmt.Errorf("ownership target file is nil")
	}
	if reference == nil {
		return fmt.Errorf("ownership reference is nil")
	}
	if err := applyFileOwnership(file, ownershipFromInfo(reference)); err != nil {
		return fmt.Errorf("inherit file ownership: %w", err)
	}
	return nil
}

// InheritRootPathOwnership applies trusted reference ownership to a path
// reached through an os.Root. It is a no-op for non-root processes and
// platforms where numeric ownership is unavailable.
func InheritRootPathOwnership(root *os.Root, name string, reference fs.FileInfo) error {
	if root == nil {
		return fmt.Errorf("ownership root is nil")
	}
	if name == "" {
		return fmt.Errorf("ownership path is empty")
	}
	if reference == nil {
		return fmt.Errorf("ownership reference is nil")
	}
	if err := applyRootPathOwnership(root, name, ownershipFromInfo(reference)); err != nil {
		return fmt.Errorf("inherit ownership for %s: %w", name, err)
	}
	return nil
}

func ownershipForReplacement(path, parent string) (fileOwnership, error) {
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode().IsRegular():
		return ownershipFromInfo(info), nil
	case err == nil:
		// Atomic replacement intentionally does not follow an existing
		// symlink. New inode ownership follows the real parent instead.
	case errors.Is(err, os.ErrNotExist):
	default:
		return fileOwnership{}, err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fileOwnership{}, err
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return fileOwnership{}, fmt.Errorf("parent is not a real directory")
	}
	return ownershipFromInfo(parentInfo), nil
}

// WriteFileAtomicPreserveDir is the non-invasive variant for files whose
// parent directory may be user-managed. It preserves an existing directory's
// mode while still rejecting a symlink at the final parent component.
func WriteFileAtomicPreserveDir(
	path string,
	data []byte,
	createDirMode fs.FileMode,
	fileMode fs.FileMode,
) error {
	dir := filepath.Dir(path)
	dirMode := createDirMode
	info, err := os.Lstat(dir)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("parent path %s must be a directory, not a symlink", dir)
		}
		dirMode = info.Mode().Perm()
	case !os.IsNotExist(err):
		return fmt.Errorf("inspect parent directory %s: %w", dir, err)
	}
	return WriteFileAtomic(path, data, dirMode, fileMode)
}

// WriteFileAtomicOwnedPreserveDir writes through a pinned parent directory and
// applies mode and explicit ownership to the temporary inode before atomic
// publication. No metadata operation follows the mutable target pathname.
func WriteFileAtomicOwnedPreserveDir(
	path string,
	data []byte,
	createDirMode fs.FileMode,
	fileMode fs.FileMode,
	uid int,
	gid int,
) (err error) {
	if path == "" {
		return fmt.Errorf("atomic owned write path is empty")
	}
	if createDirMode.Perm() != createDirMode || fileMode.Perm() != fileMode {
		return fmt.Errorf("atomic owned write modes must contain permission bits only")
	}

	dir := filepath.Dir(path)
	var originalParent fs.FileInfo
	parentInfo, statErr := os.Lstat(dir)
	switch {
	case statErr == nil:
		if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
			return fmt.Errorf("parent path %s must be a directory, not a symlink", dir)
		}
		originalParent = parentInfo
	case errors.Is(statErr, os.ErrNotExist):
		if err := EnsureDir(dir, createDirMode); err != nil {
			return fmt.Errorf("prepare parent directory %s: %w", dir, err)
		}
	default:
		return fmt.Errorf("inspect parent directory %s: %w", dir, statErr)
	}

	root, openedParent, err := OpenVerifiedRoot(dir)
	if err != nil {
		return fmt.Errorf("pin parent directory %s: %w", dir, err)
	}
	defer root.Close()
	if originalParent != nil && !os.SameFile(originalParent, openedParent) {
		return fmt.Errorf("parent directory %s changed before it was pinned", dir)
	}

	targetName := filepath.Base(path)
	if targetName == "." || targetName == string(filepath.Separator) {
		return fmt.Errorf("atomic owned write target is invalid")
	}
	return writeFileAtomicOwnedInRoot(
		root,
		path,
		targetName,
		data,
		fileMode,
		uid,
		gid,
	)
}

// WriteFileAtomicOwnedAt writes a root-relative file through a pinned
// directory chain. Every existing directory component must be a real
// directory, newly created components inherit their pinned parent's
// ownership, and the replacement inode receives its final mode and ownership
// before publication.
func WriteFileAtomicOwnedAt(
	rootPath string,
	name string,
	data []byte,
	createDirMode fs.FileMode,
	fileMode fs.FileMode,
	uid int,
	gid int,
) error {
	if createDirMode.Perm() != createDirMode || fileMode.Perm() != fileMode {
		return fmt.Errorf("atomic owned write modes must contain permission bits only")
	}
	cleanedName, err := cleanRootRelativeName(name, false)
	if err != nil {
		return fmt.Errorf("atomic owned write path: %w", err)
	}
	root, _, err := OpenVerifiedRoot(rootPath)
	if err != nil {
		return fmt.Errorf("pin atomic owned write root %s: %w", rootPath, err)
	}
	defer root.Close()

	parent, err := openPinnedRootDirectoryAt(
		root,
		filepath.Dir(cleanedName),
		true,
		createDirMode,
	)
	if err != nil {
		return fmt.Errorf("pin atomic owned write parent for %s: %w", name, err)
	}
	defer parent.Close()
	return writeFileAtomicOwnedInRoot(
		parent,
		filepath.Join(rootPath, cleanedName),
		filepath.Base(cleanedName),
		data,
		fileMode,
		uid,
		gid,
	)
}

func writeFileAtomicOwnedInRoot(
	root *os.Root,
	displayPath string,
	targetName string,
	data []byte,
	fileMode fs.FileMode,
	uid int,
	gid int,
) (err error) {
	temp, tempName, err := createRootTemporaryFile(root, targetName)
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", displayPath, err)
	}
	defer func() {
		if temp != nil {
			_ = temp.Close()
		}
		if err != nil {
			_ = root.Remove(tempName)
		}
	}()

	if err = applyExplicitFileOwnership(temp, uid, gid); err != nil {
		return fmt.Errorf("set temporary file ownership for %s: %w", displayPath, err)
	}
	if err = temp.Chmod(fileMode); err != nil {
		return fmt.Errorf("set temporary file mode for %s: %w", displayPath, err)
	}
	written, writeErr := temp.Write(data)
	if writeErr != nil {
		return fmt.Errorf("write temporary file for %s: %w", displayPath, writeErr)
	}
	if written != len(data) {
		return fmt.Errorf(
			"write temporary file for %s: wrote %d bytes, expected %d",
			displayPath,
			written,
			len(data),
		)
	}
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary file for %s: %w", displayPath, err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("close temporary file for %s: %w", displayPath, err)
	}
	temp = nil

	if err = root.Rename(tempName, targetName); err != nil {
		return fmt.Errorf("replace %s atomically: %w", displayPath, err)
	}
	parent, openErr := root.Open(".")
	if openErr != nil {
		return fmt.Errorf("open pinned parent directory for %s: %w", displayPath, openErr)
	}
	defer parent.Close()
	if err = parent.Sync(); err != nil {
		return fmt.Errorf("sync parent directory for %s: %w", displayPath, err)
	}
	return nil
}

// RepairRegularFileMetadata pins a regular file through its parent directory
// and applies mode and ownership to the opened inode.
func RepairRegularFileMetadata(
	path string,
	mode fs.FileMode,
	uid int,
	gid int,
) error {
	if path == "" {
		return fmt.Errorf("metadata repair path is empty")
	}
	if mode.Perm() != mode {
		return fmt.Errorf("metadata repair mode must contain permission bits only")
	}
	dir := filepath.Dir(path)
	root, _, err := OpenVerifiedRoot(dir)
	if err != nil {
		return fmt.Errorf("pin metadata parent %s: %w", dir, err)
	}
	defer root.Close()

	name := filepath.Base(path)
	return repairRegularFileMetadataInRoot(root, path, name, mode, uid, gid)
}

// RepairRegularFileMetadataAt applies metadata to the exact regular inode
// opened below a pinned root. Intermediate and final symlinks are rejected.
func RepairRegularFileMetadataAt(
	rootPath string,
	name string,
	mode fs.FileMode,
	uid int,
	gid int,
) error {
	if mode.Perm() != mode {
		return fmt.Errorf("metadata repair mode must contain permission bits only")
	}
	cleanedName, err := cleanRootRelativeName(name, false)
	if err != nil {
		return fmt.Errorf("metadata repair path: %w", err)
	}
	root, _, err := OpenVerifiedRoot(rootPath)
	if err != nil {
		return fmt.Errorf("pin metadata root %s: %w", rootPath, err)
	}
	defer root.Close()
	parent, err := openPinnedRootDirectoryAt(
		root,
		filepath.Dir(cleanedName),
		false,
		0,
	)
	if err != nil {
		return fmt.Errorf("pin metadata parent for %s: %w", name, err)
	}
	defer parent.Close()
	return repairRegularFileMetadataInRoot(
		parent,
		filepath.Join(rootPath, cleanedName),
		filepath.Base(cleanedName),
		mode,
		uid,
		gid,
	)
}

func repairRegularFileMetadataInRoot(
	root *os.Root,
	displayPath string,
	name string,
	mode fs.FileMode,
	uid int,
	gid int,
) error {
	before, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", displayPath)
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return fmt.Errorf("%s changed while it was being opened", displayPath)
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("set mode for %s: %w", displayPath, err)
	}
	if err := applyExplicitFileOwnership(file, uid, gid); err != nil {
		return fmt.Errorf("set ownership for %s: %w", displayPath, err)
	}
	return nil
}

// ChownRealDirectory applies ownership to a verified directory descriptor.
// If the pathname is concurrently replaced, the operation remains bound to
// the directory that was opened.
func ChownRealDirectory(path string, uid, gid int) error {
	root, _, err := OpenVerifiedRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	return chownPinnedRootDirectory(root, path, uid, gid)
}

// ChownRealDirectoryAt applies ownership to a directory reached through a
// pinned managed root. Every child component is opened and inode-verified
// before the next component is used, so a concurrent rename or symlink swap
// cannot redirect ownership outside the managed root.
func ChownRealDirectoryAt(rootPath, targetPath string, uid, gid int) error {
	relative, err := relativePathWithinRoot(rootPath, targetPath)
	if err != nil {
		return err
	}
	root, _, err := OpenVerifiedRoot(rootPath)
	if err != nil {
		return fmt.Errorf("pin ownership root %s: %w", rootPath, err)
	}
	defer root.Close()
	target, err := openPinnedRootDirectoryAt(root, relative, false, 0)
	if err != nil {
		return fmt.Errorf("pin ownership target %s: %w", targetPath, err)
	}
	defer target.Close()
	return chownPinnedRootDirectory(target, targetPath, uid, gid)
}

func chownPinnedRootDirectory(
	root *os.Root,
	displayPath string,
	uid int,
	gid int,
) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open pinned directory %s: %w", displayPath, err)
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil || !info.IsDir() {
		return fmt.Errorf("pinned ownership target %s is not a directory", displayPath)
	}
	if err := applyExplicitFileOwnership(directory, uid, gid); err != nil {
		return fmt.Errorf("set directory ownership for %s: %w", displayPath, err)
	}
	return nil
}

func cleanRootRelativeName(name string, allowRoot bool) (string, error) {
	if name == "" || filepath.IsAbs(name) {
		return "", fmt.Errorf("root-relative path is invalid")
	}
	cleaned := filepath.Clean(name)
	if cleaned == "." {
		if allowRoot {
			return cleaned, nil
		}
		return "", fmt.Errorf("root-relative path must name a child")
	}
	if cleaned == ".." ||
		strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("root-relative path escapes its root")
	}
	return cleaned, nil
}

func relativePathWithinRoot(rootPath, targetPath string) (string, error) {
	if rootPath == "" || targetPath == "" {
		return "", fmt.Errorf("ownership root and target are required")
	}
	root, err := filepath.Abs(rootPath)
	if err != nil {
		return "", fmt.Errorf("resolve ownership root: %w", err)
	}
	target, err := filepath.Abs(targetPath)
	if err != nil {
		return "", fmt.Errorf("resolve ownership target: %w", err)
	}
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil {
		return "", err
	}
	cleaned, err := cleanRootRelativeName(relative, true)
	if err != nil {
		return "", fmt.Errorf("%s is outside ownership root %s", targetPath, rootPath)
	}
	return cleaned, nil
}

func openPinnedRootDirectoryAt(
	root *os.Root,
	name string,
	create bool,
	createMode fs.FileMode,
) (*os.Root, error) {
	if root == nil {
		return nil, fmt.Errorf("directory root is nil")
	}
	if createMode.Perm() != createMode {
		return nil, fmt.Errorf("directory mode must contain permission bits only")
	}
	cleaned, err := cleanRootRelativeName(name, true)
	if err != nil {
		return nil, err
	}
	current, err := root.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	if cleaned == "." {
		return current, nil
	}

	for _, component := range strings.Split(cleaned, string(filepath.Separator)) {
		parentInfo, statErr := current.Stat(".")
		if statErr != nil {
			_ = current.Close()
			return nil, statErr
		}
		before, statErr := current.Lstat(component)
		created := false
		if errors.Is(statErr, os.ErrNotExist) && create {
			mkdirErr := current.Mkdir(component, createMode)
			if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				_ = current.Close()
				return nil, mkdirErr
			}
			before, statErr = current.Lstat(component)
			created = mkdirErr == nil && statErr == nil
		}
		if statErr != nil {
			_ = current.Close()
			return nil, statErr
		}
		if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			_ = current.Close()
			return nil, fmt.Errorf("%s must be a real directory", component)
		}
		next, openErr := current.OpenRoot(component)
		if openErr != nil {
			_ = current.Close()
			return nil, openErr
		}
		opened, openErr := next.Stat(".")
		if openErr != nil || !opened.IsDir() || !os.SameFile(before, opened) {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("%s changed while it was being opened", component)
		}
		if created {
			directory, openFileErr := next.Open(".")
			if openFileErr != nil {
				_ = next.Close()
				_ = current.Close()
				return nil, openFileErr
			}
			if chmodErr := directory.Chmod(createMode); chmodErr != nil {
				_ = directory.Close()
				_ = next.Close()
				_ = current.Close()
				return nil, chmodErr
			}
			if ownershipErr := InheritFileOwnership(directory, parentInfo); ownershipErr != nil {
				_ = directory.Close()
				_ = next.Close()
				_ = current.Close()
				return nil, ownershipErr
			}
			if closeErr := directory.Close(); closeErr != nil {
				_ = next.Close()
				_ = current.Close()
				return nil, closeErr
			}
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

// OpenPinnedDirectoryAt walks a root-relative directory one component at a
// time, rejects symlinks, and verifies every opened inode. When create is true,
// missing directories are created through their already pinned parent.
func OpenPinnedDirectoryAt(
	root *os.Root,
	name string,
	create bool,
	createMode fs.FileMode,
) (*os.Root, error) {
	return openPinnedRootDirectoryAt(root, name, create, createMode)
}

func createRootTemporaryFile(root *os.Root, targetName string) (*os.File, string, error) {
	for attempt := 0; attempt < 64; attempt++ {
		randomBytes := make([]byte, 8)
		if _, err := rand.Read(randomBytes); err != nil {
			return nil, "", err
		}
		tempName := "." + targetName + ".tmp-" + hex.EncodeToString(randomBytes)
		file, err := root.OpenFile(tempName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return file, tempName, err
	}
	return nil, "", fmt.Errorf("temporary filename collision limit reached")
}

// WriteReaderAtomicPreserveDir is the streaming variant for files whose
// parent directory may be user-managed.
func WriteReaderAtomicPreserveDir(
	path string,
	source io.Reader,
	expectedSize int64,
	createDirMode fs.FileMode,
	fileMode fs.FileMode,
) error {
	dir := filepath.Dir(path)
	dirMode := createDirMode
	info, err := os.Lstat(dir)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("parent path %s must be a directory, not a symlink", dir)
		}
		dirMode = info.Mode().Perm()
	case !os.IsNotExist(err):
		return fmt.Errorf("inspect parent directory %s: %w", dir, err)
	}
	return WriteReaderAtomic(
		path,
		source,
		expectedSize,
		dirMode,
		fileMode,
	)
}
