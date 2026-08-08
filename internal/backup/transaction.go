package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/get-sdbx/sdbx/internal/securefs"
)

const (
	restoreJournalName    = ".sdbx-restore-transaction.jsonl"
	restoreJournalVersion = 1
	restoreTransactionTag = ".sdbx-restore-"
	maxRestoreJournalSize = int64(256 << 20)
)

type restoreRootKind string

const (
	restoreRootProject restoreRootKind = "project"
	restoreRootConfig  restoreRootKind = "config"
	restoreRootSecrets restoreRootKind = "secrets"
)

const (
	restoreEventHeader   = "header"
	restoreEventBegin    = "begin"
	restoreEventBackedUp = "backed_up"
	restoreEventPromoted = "promoted"
	restoreEventCommit   = "commit"
)

// errSimulatedRestoreCrash is reachable only through the package-private test
// hook. It deliberately leaves the journal intact so recovery can be tested.
var errSimulatedRestoreCrash = errors.New("simulated restore process interruption")

type restoreJournalRecord struct {
	Event       string          `json:"event"`
	Version     int             `json:"version,omitempty"`
	ID          string          `json:"id,omitempty"`
	ProjectPath string          `json:"project_path,omitempty"`
	ConfigPath  string          `json:"config_path,omitempty"`
	SecretsPath string          `json:"secrets_path,omitempty"`
	Root        restoreRootKind `json:"root,omitempty"`
	Target      string          `json:"target,omitempty"`
	Existed     bool            `json:"existed,omitempty"`
	CreatedDirs []string        `json:"created_dirs,omitempty"`
}

type restoreJournalHeader struct {
	ID          string
	ProjectPath string
	ConfigPath  string
	SecretsPath string
}

type restoreJournalOperation struct {
	Root        restoreRootKind
	Target      string
	Existed     bool
	CreatedDirs []string
	BackedUp    bool
	Promoted    bool
}

type restoreJournalState struct {
	Header     restoreJournalHeader
	Operations []*restoreJournalOperation
	Committed  bool
}

type restoreJournalWriter struct {
	file *os.File
	size int64
}

type stagedRestoreFile struct {
	rootKind restoreRootKind
	target   string
	mode     fs.FileMode
}

type restoreSelection struct {
	preserveProject bool
	skipConfigPaths map[string]struct{}
}

func applyArchiveTransactional(
	ctx context.Context,
	file *os.File,
	identities []age.Identity,
	targets restoreTargets,
	hook func(phase, target string) error,
	hooks RestoreHooks,
) (returnErr error) {
	selection, err := prepareRestoreSelection(hooks)
	if err != nil {
		return err
	}
	roots, err := openRestoreRootsAt(
		targets.projectPath,
		targets.configPath,
		targets.secretsPath,
		true,
	)
	if err != nil {
		return err
	}
	defer roots.Close()
	transactionID, err := newRestoreTransactionID()
	if err != nil {
		return err
	}
	header := restoreJournalHeader{
		ID:          transactionID,
		ProjectPath: roots.projectPath,
		ConfigPath:  roots.configPath,
		SecretsPath: roots.secretsPath,
	}
	journal, err := createRestoreJournal(roots.project, header)
	if err != nil {
		return err
	}
	journalOpen := true
	defer func() {
		if journalOpen {
			_ = journal.close()
		}
	}()

	fail := func(operationErr error) error {
		if closeErr := journal.close(); closeErr != nil {
			operationErr = errors.Join(operationErr, fmt.Errorf("close restore journal: %w", closeErr))
		}
		journalOpen = false
		if errors.Is(operationErr, errSimulatedRestoreCrash) {
			return operationErr
		}
		recoveryErr := recoverRestoreTransaction(roots.projectPath)
		if recoveryErr != nil {
			return errors.Join(
				operationErr,
				fmt.Errorf("roll back restore transaction: %w", recoveryErr),
			)
		}
		return operationErr
	}

	if err := createRestoreTransactionDirs(roots, transactionID); err != nil {
		return fail(fmt.Errorf("prepare restore transaction: %w", err))
	}
	staged, err := stageRestoreArchive(
		ctx,
		file,
		identities,
		roots,
		transactionID,
		selection,
		hooks.InspectProjectFile,
	)
	if err != nil {
		return fail(fmt.Errorf("stage restore archive: %w", err))
	}
	if err := callRestoreHook(hook, "after-stage", ""); err != nil {
		return fail(err)
	}
	if hooks.ValidateArchive != nil {
		if err := hooks.ValidateArchive(); err != nil {
			return fail(fmt.Errorf("validate staged restore selection: %w", err))
		}
	}
	for _, stagedFile := range staged {
		if err := promoteStagedRestoreFile(
			roots,
			transactionID,
			stagedFile,
			journal,
			hook,
		); err != nil {
			return fail(err)
		}
	}
	if err := callRestoreHook(hook, "before-commit", ""); err != nil {
		return fail(err)
	}
	if hooks.Validate != nil {
		if err := hooks.Validate(ctx); err != nil {
			return fail(fmt.Errorf("validate restored project: %w", err))
		}
	}
	if err := journal.append(restoreJournalRecord{Event: restoreEventCommit}); err != nil {
		return fail(fmt.Errorf("commit restore journal: %w", err))
	}
	if err := journal.close(); err != nil {
		journalOpen = false
		return fmt.Errorf("restore committed but journal close failed: %w", err)
	}
	journalOpen = false
	if err := cleanupRestoreTransaction(roots, transactionID); err != nil {
		return fmt.Errorf("restore committed but transaction cleanup failed: %w", err)
	}
	if err := removeRestoreJournal(roots.project); err != nil {
		return fmt.Errorf("restore committed but journal cleanup failed: %w", err)
	}
	return nil
}

func stageRestoreArchive(
	ctx context.Context,
	file *os.File,
	identities []age.Identity,
	roots *restoreRoots,
	transactionID string,
	selection restoreSelection,
	inspectProjectFile func(name string, data []byte) error,
) ([]stagedRestoreFile, error) {
	archive, closeReader, err := openArchive(file, identities)
	if err != nil {
		return nil, err
	}
	readerClosed := false
	defer func() {
		if !readerClosed {
			_ = closeReader(false)
		}
	}()

	staged := make([]stagedRestoreFile, 0, 64)
	seen := make(map[string]struct{})
	var entries int
	var total int64
	var pathBytes int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := archive.Next()
		if err == io.EOF {
			if entries == 0 {
				return nil, fmt.Errorf("archive is empty")
			}
			if selection.preserveProject {
				for _, required := range []string{".sdbx.yaml", ".sdbx.lock"} {
					if _, ok := seen[required]; !ok {
						return nil, fmt.Errorf(
							"portable state restore requires archived %s",
							required,
						)
					}
				}
			}
			if err := closeReader(true); err != nil {
				return nil, fmt.Errorf("finish encrypted archive: %w", err)
			}
			readerClosed = true
			return staged, nil
		}
		if err != nil {
			return nil, err
		}
		entries++
		if err := validateRestoreEntryCount(entries); err != nil {
			return nil, err
		}
		cleaned, err := validateArchiveHeader(header, entries == 1)
		if err != nil {
			return nil, err
		}
		if err := validateRestorePathBudget(cleaned, &pathBytes); err != nil {
			return nil, err
		}
		if _, duplicate := seen[cleaned]; duplicate {
			return nil, fmt.Errorf("archive contains duplicate entry %q", cleaned)
		}
		seen[cleaned] = struct{}{}
		if err := validateRestoreSize(header, total); err != nil {
			return nil, fmt.Errorf("entry %q: %w", cleaned, err)
		}
		if err := validateManagedRestoreSize(cleaned, header.Size); err != nil {
			return nil, fmt.Errorf("entry %q: %w", cleaned, err)
		}
		total += header.Size
		if cleaned == "metadata.json" {
			if err := validateStagedMetadata(ctx, archive, header.Size); err != nil {
				return nil, err
			}
			continue
		}

		rootKind, root, target, forcePrivate := roots.destinationRecord(cleaned)
		skip := selection.shouldSkip(rootKind, target)
		if rootKind == restoreRootProject && inspectProjectFile != nil {
			data, err := readExactRestoreEntry(ctx, archive, header.Size)
			if err != nil {
				return nil, fmt.Errorf("inspect %q: %w", cleaned, err)
			}
			if err := inspectProjectFile(cleaned, data); err != nil {
				return nil, fmt.Errorf("inspect archived %q: %w", cleaned, err)
			}
			if skip {
				continue
			}
			mode := validatedRestoreMode(header.Mode)
			if forcePrivate {
				mode = 0o600
			}
			if err := stageRestoreFile(
				ctx,
				root,
				transactionID,
				target,
				mode,
				bytes.NewReader(data),
				header.Size,
			); err != nil {
				return nil, fmt.Errorf("stage %q: %w", cleaned, err)
			}
			staged = append(staged, stagedRestoreFile{
				rootKind: rootKind,
				target:   target,
				mode:     mode,
			})
			continue
		}
		if skip {
			if err := discardExactRestoreEntry(ctx, archive, header.Size); err != nil {
				return nil, fmt.Errorf("skip %q: %w", cleaned, err)
			}
			continue
		}
		mode := validatedRestoreMode(header.Mode)
		if forcePrivate {
			mode = 0o600
		}
		if err := stageRestoreFile(
			ctx,
			root,
			transactionID,
			target,
			mode,
			archive,
			header.Size,
		); err != nil {
			return nil, fmt.Errorf("stage %q: %w", cleaned, err)
		}
		staged = append(staged, stagedRestoreFile{
			rootKind: rootKind,
			target:   target,
			mode:     mode,
		})
	}
}

func validatedRestoreMode(value int64) fs.FileMode {
	// #nosec G115 -- validateArchiveHeader limits value to the non-negative
	// Unix permission bits before this conversion is reachable.
	return fs.FileMode(uint32(value)).Perm()
}

func prepareRestoreSelection(hooks RestoreHooks) (restoreSelection, error) {
	selection := restoreSelection{
		preserveProject: hooks.PreserveProject,
		skipConfigPaths: make(map[string]struct{}, len(hooks.SkipConfigPaths)),
	}
	if !hooks.PreserveProject && len(hooks.SkipConfigPaths) > 0 {
		return restoreSelection{}, fmt.Errorf(
			"config restore exclusions require PreserveProject",
		)
	}
	for _, path := range hooks.SkipConfigPaths {
		clean := filepath.Clean(filepath.FromSlash(path))
		if err := validateRestoreRelativePath(clean); err != nil {
			return restoreSelection{}, fmt.Errorf("invalid skipped config path: %w", err)
		}
		if _, duplicate := selection.skipConfigPaths[clean]; duplicate {
			return restoreSelection{}, fmt.Errorf("duplicate skipped config path %q", path)
		}
		selection.skipConfigPaths[clean] = struct{}{}
	}
	return selection, nil
}

func (s restoreSelection) shouldSkip(
	rootKind restoreRootKind,
	target string,
) bool {
	if s.preserveProject && rootKind == restoreRootProject {
		return true
	}
	if rootKind == restoreRootConfig {
		_, skip := s.skipConfigPaths[target]
		return skip
	}
	return false
}

func readExactRestoreEntry(
	ctx context.Context,
	source io.Reader,
	size int64,
) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(
		&contextReader{ctx: ctx, reader: source},
		size+1,
	))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, fmt.Errorf("read %d bytes, expected %d", len(data), size)
	}
	return data, nil
}

func discardExactRestoreEntry(
	ctx context.Context,
	source io.Reader,
	size int64,
) error {
	written, err := io.CopyN(
		io.Discard,
		&contextReader{ctx: ctx, reader: source},
		size,
	)
	if err != nil {
		return err
	}
	if written != size {
		return fmt.Errorf("read %d bytes, expected %d", written, size)
	}
	return nil
}

func validateStagedMetadata(ctx context.Context, source io.Reader, size int64) error {
	if size > maxMetadataBytes {
		return fmt.Errorf("metadata exceeds %d bytes", maxMetadataBytes)
	}
	data, err := io.ReadAll(io.LimitReader(
		&contextReader{ctx: ctx, reader: source},
		size+1,
	))
	if err != nil {
		return err
	}
	if int64(len(data)) != size {
		return fmt.Errorf("metadata size does not match its header")
	}
	var metadata Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return fmt.Errorf("invalid metadata: %w", err)
	}
	if metadata.Version != "2.0.0" {
		return fmt.Errorf("unsupported backup metadata version %q", metadata.Version)
	}
	return nil
}

func stageRestoreFile(
	ctx context.Context,
	root *os.Root,
	transactionID, target string,
	mode fs.FileMode,
	source io.Reader,
	size int64,
) (returnErr error) {
	if target == "." {
		return fmt.Errorf("regular file cannot target a restore root")
	}
	stageName := restoreStageName(transactionID, target)
	parent := filepath.Dir(stageName)
	stageRoot, err := securefs.OpenPinnedDirectoryAt(root, parent, true, 0o700)
	if err != nil {
		return err
	}
	defer stageRoot.Close()
	stagedFile, err := stageRoot.OpenFile(
		filepath.Base(stageName),
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		mode.Perm(),
	)
	if err != nil {
		return err
	}
	defer func() {
		_ = stagedFile.Close()
		if returnErr != nil {
			_ = stageRoot.Remove(filepath.Base(stageName))
		}
	}()
	if err := stagedFile.Chmod(mode.Perm()); err != nil {
		return err
	}
	written, err := io.Copy(
		stagedFile,
		&contextReader{ctx: ctx, reader: io.LimitReader(source, size)},
	)
	if err != nil {
		return err
	}
	if written != size {
		return fmt.Errorf("staged %d bytes, expected %d", written, size)
	}
	if err := stagedFile.Sync(); err != nil {
		return err
	}
	if err := stagedFile.Close(); err != nil {
		return err
	}
	return syncRootDirectory(stageRoot, ".")
}

func promoteStagedRestoreFile(
	roots *restoreRoots,
	transactionID string,
	staged stagedRestoreFile,
	journal *restoreJournalWriter,
	hook func(phase, target string) error,
) error {
	root, _, err := roots.rootForKind(staged.rootKind)
	if err != nil {
		return err
	}
	if err := ensureRootParentsNoSymlink(root, staged.target); err != nil {
		return err
	}
	existing, existed, err := existingRestoreTarget(root, staged.target)
	if err != nil {
		return err
	}
	createdDirs, reference, err := missingRestoreDirectories(root, staged.target)
	if err != nil {
		return err
	}
	if existed {
		reference = existing
	}

	stageName := restoreStageName(transactionID, staged.target)
	stageParent, err := securefs.OpenPinnedDirectoryAt(
		root,
		filepath.Dir(stageName),
		false,
		0,
	)
	if err != nil {
		return err
	}
	defer stageParent.Close()
	stageBase := filepath.Base(stageName)
	stagedBefore, err := stageParent.Lstat(stageBase)
	if err != nil {
		return err
	}
	if stagedBefore.Mode()&os.ModeSymlink != 0 || !stagedBefore.Mode().IsRegular() {
		return fmt.Errorf("staged restore file %q is not regular", staged.target)
	}
	stagedHandle, err := stageParent.OpenFile(stageBase, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	stagedOpened, err := stagedHandle.Stat()
	if err != nil ||
		!stagedOpened.Mode().IsRegular() ||
		!os.SameFile(stagedBefore, stagedOpened) {
		_ = stagedHandle.Close()
		if err != nil {
			return err
		}
		return fmt.Errorf("staged restore file %q changed while opening", staged.target)
	}
	if err := securefs.InheritFileOwnership(stagedHandle, reference); err != nil {
		_ = stagedHandle.Close()
		return err
	}
	if err := stagedHandle.Chmod(staged.mode.Perm()); err != nil {
		_ = stagedHandle.Close()
		return err
	}
	if err := stagedHandle.Sync(); err != nil {
		_ = stagedHandle.Close()
		return err
	}
	if err := stagedHandle.Close(); err != nil {
		return err
	}

	operation := restoreJournalRecord{
		Event:       restoreEventBegin,
		Root:        staged.rootKind,
		Target:      staged.target,
		Existed:     existed,
		CreatedDirs: createdDirs,
	}
	if err := journal.append(operation); err != nil {
		return fmt.Errorf("journal restore of %q: %w", staged.target, err)
	}
	directoryMode := fs.FileMode(0o755)
	if staged.rootKind == restoreRootSecrets {
		directoryMode = 0o700
	}
	if err := createRestoreDirectories(root, createdDirs, directoryMode); err != nil {
		return err
	}
	targetParent, targetBase, err := openRestoreTargetParent(root, staged.target)
	if err != nil {
		return err
	}
	defer targetParent.Close()
	current, currentExists, err := lstatOptional(targetParent, targetBase)
	if err != nil {
		return err
	}
	if existed {
		if !currentExists ||
			current.Mode()&os.ModeSymlink != 0 ||
			!current.Mode().IsRegular() ||
			!os.SameFile(existing, current) {
			return fmt.Errorf("restore target %q changed before promotion", staged.target)
		}
	} else if currentExists {
		return fmt.Errorf("restore target %q appeared before promotion", staged.target)
	}

	var rollbackParent *os.Root
	rollbackName := restoreRollbackName(transactionID, staged.target)
	rollbackBase := filepath.Base(rollbackName)
	if existed {
		rollbackParent, err = securefs.OpenPinnedDirectoryAt(
			root,
			filepath.Dir(rollbackName),
			true,
			0o700,
		)
		if err != nil {
			return err
		}
		defer rollbackParent.Close()
		if _, rollbackExists, err := lstatOptional(
			rollbackParent,
			rollbackBase,
		); err != nil {
			return err
		} else if rollbackExists {
			return fmt.Errorf("restore rollback file %q already exists", staged.target)
		}
	}
	if err := callRestoreHook(hook, "before-promote", staged.target); err != nil {
		return err
	}
	if existed {
		if err := securefs.RenameBaseAt(
			targetParent,
			targetBase,
			rollbackParent,
			rollbackBase,
		); err != nil {
			return err
		}
		if err := syncRootDirectory(targetParent, "."); err != nil {
			return err
		}
		if err := syncRootDirectory(rollbackParent, "."); err != nil {
			return err
		}
		if err := journal.append(restoreJournalRecord{
			Event:  restoreEventBackedUp,
			Root:   staged.rootKind,
			Target: staged.target,
		}); err != nil {
			return err
		}
		if err := callRestoreHook(hook, "after-backup", staged.target); err != nil {
			return err
		}
	}
	if err := securefs.RenameBaseAt(
		stageParent,
		stageBase,
		targetParent,
		targetBase,
	); err != nil {
		return err
	}
	if err := syncRootDirectory(stageParent, "."); err != nil {
		return err
	}
	if err := syncRootDirectory(targetParent, "."); err != nil {
		return err
	}
	if err := journal.append(restoreJournalRecord{
		Event:  restoreEventPromoted,
		Root:   staged.rootKind,
		Target: staged.target,
	}); err != nil {
		return err
	}
	return callRestoreHook(hook, "after-promote", staged.target)
}

func openRestoreTargetParent(
	root *os.Root,
	target string,
) (*os.Root, string, error) {
	if err := validateRestoreRelativePath(target); err != nil {
		return nil, "", err
	}
	parent, err := securefs.OpenPinnedDirectoryAt(
		root,
		filepath.Dir(target),
		false,
		0,
	)
	if err != nil {
		return nil, "", err
	}
	return parent, filepath.Base(target), nil
}

func existingRestoreTarget(
	root *os.Root,
	target string,
) (fs.FileInfo, bool, error) {
	info, err := root.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("existing target %q is a symlink or special file", target)
	}
	return info, true, nil
}

func missingRestoreDirectories(
	root *os.Root,
	target string,
) ([]string, fs.FileInfo, error) {
	parent := filepath.Dir(target)
	if parent == "." {
		info, err := root.Stat(".")
		return nil, info, err
	}
	var reverse []string
	current := parent
	for current != "." && current != "" {
		info, err := root.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return nil, nil, fmt.Errorf(
					"restore parent %q is a symlink or non-directory",
					current,
				)
			}
			created := make([]string, len(reverse))
			for index := range reverse {
				created[index] = reverse[len(reverse)-1-index]
			}
			return created, info, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
		reverse = append(reverse, current)
		next := filepath.Dir(current)
		if next == current {
			break
		}
		current = next
	}
	info, err := root.Stat(".")
	if err != nil {
		return nil, nil, err
	}
	created := make([]string, len(reverse))
	for index := range reverse {
		created[index] = reverse[len(reverse)-1-index]
	}
	return created, info, nil
}

func createRestoreDirectories(
	root *os.Root,
	directories []string,
	mode fs.FileMode,
) error {
	for _, directory := range directories {
		parent := filepath.Dir(directory)
		parentRoot, err := securefs.OpenPinnedDirectoryAt(root, parent, false, 0)
		if err != nil {
			return err
		}
		parentInfo, err := parentRoot.Stat(".")
		if err != nil {
			_ = parentRoot.Close()
			return err
		}
		base := filepath.Base(directory)
		if err := parentRoot.Mkdir(base, mode.Perm()); err != nil {
			_ = parentRoot.Close()
			return err
		}
		createdBefore, err := parentRoot.Lstat(base)
		if err != nil {
			_ = parentRoot.Close()
			return err
		}
		createdRoot, err := securefs.OpenPinnedDirectoryAt(parentRoot, base, false, 0)
		if err != nil {
			_ = parentRoot.Close()
			return err
		}
		createdOpened, err := createdRoot.Stat(".")
		if err != nil || !os.SameFile(createdBefore, createdOpened) {
			_ = createdRoot.Close()
			_ = parentRoot.Close()
			if err != nil {
				return err
			}
			return fmt.Errorf("restore directory %q changed while opening", directory)
		}
		createdHandle, err := createdRoot.Open(".")
		if err != nil {
			_ = createdRoot.Close()
			_ = parentRoot.Close()
			return err
		}
		if err := createdHandle.Chmod(mode.Perm()); err != nil {
			_ = createdHandle.Close()
			_ = createdRoot.Close()
			_ = parentRoot.Close()
			return err
		}
		if err := securefs.InheritFileOwnership(createdHandle, parentInfo); err != nil {
			_ = createdHandle.Close()
			_ = createdRoot.Close()
			_ = parentRoot.Close()
			return err
		}
		if err := createdHandle.Close(); err != nil {
			_ = createdRoot.Close()
			_ = parentRoot.Close()
			return err
		}
		if err := syncRootDirectory(createdRoot, "."); err != nil {
			_ = createdRoot.Close()
			_ = parentRoot.Close()
			return err
		}
		if err := createdRoot.Close(); err != nil {
			_ = parentRoot.Close()
			return err
		}
		if err := syncRootDirectory(parentRoot, "."); err != nil {
			_ = parentRoot.Close()
			return err
		}
		if err := parentRoot.Close(); err != nil {
			return err
		}
	}
	return nil
}

func createRestoreTransactionDirs(roots *restoreRoots, transactionID string) error {
	for _, root := range []*os.Root{roots.project, roots.config, roots.secrets} {
		transactionDir := restoreTransactionName(transactionID)
		if err := root.Mkdir(transactionDir, 0o700); err != nil {
			return err
		}
		if err := root.Chmod(transactionDir, 0o700); err != nil {
			return err
		}
		if err := root.Mkdir(filepath.Join(transactionDir, "stage"), 0o700); err != nil {
			return err
		}
		if err := root.Mkdir(filepath.Join(transactionDir, "rollback"), 0o700); err != nil {
			return err
		}
		if err := syncRootDirectory(root, transactionDir); err != nil {
			return err
		}
		if err := syncRootDirectory(root, "."); err != nil {
			return err
		}
	}
	return nil
}

func createRestoreJournal(
	projectRoot *os.Root,
	header restoreJournalHeader,
) (*restoreJournalWriter, error) {
	if info, err := projectRoot.Lstat(restoreJournalName); err == nil {
		return nil, fmt.Errorf(
			"restore journal already exists as %s",
			info.Mode().Type(),
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := projectRoot.OpenFile(
		restoreJournalName,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	writer := &restoreJournalWriter{file: file}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = projectRoot.Remove(restoreJournalName)
		return nil, err
	}
	if err := writer.append(restoreJournalRecord{
		Event:       restoreEventHeader,
		Version:     restoreJournalVersion,
		ID:          header.ID,
		ProjectPath: header.ProjectPath,
		ConfigPath:  header.ConfigPath,
		SecretsPath: header.SecretsPath,
	}); err != nil {
		_ = file.Close()
		_ = projectRoot.Remove(restoreJournalName)
		return nil, err
	}
	if err := syncRootDirectory(projectRoot, "."); err != nil {
		_ = file.Close()
		_ = projectRoot.Remove(restoreJournalName)
		return nil, err
	}
	return writer, nil
}

func (w *restoreJournalWriter) append(record restoreJournalRecord) error {
	if w == nil || w.file == nil {
		return fmt.Errorf("restore journal is closed")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	recordSize := int64(len(data))
	if w.size < 0 || recordSize > maxRestoreJournalSize-w.size {
		return fmt.Errorf("restore journal exceeds %d bytes", maxRestoreJournalSize)
	}
	written, err := w.file.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	w.size += recordSize
	return w.file.Sync()
}

func (w *restoreJournalWriter) close() error {
	if w == nil || w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func recoverRestoreTransaction(projectPath string) error {
	projectPath, err := filepath.Abs(projectPath)
	if err != nil {
		return err
	}
	projectPath = filepath.Clean(projectPath)
	projectRoot, err := os.OpenRoot(projectPath)
	if err != nil {
		return err
	}
	state, exists, err := loadRestoreJournal(projectRoot, projectPath)
	_ = projectRoot.Close()
	if err != nil || !exists {
		return err
	}
	roots, err := openRestoreRootsAt(
		state.Header.ProjectPath,
		state.Header.ConfigPath,
		state.Header.SecretsPath,
		false,
	)
	if err != nil {
		return err
	}
	defer roots.Close()
	if !state.Committed {
		for index := len(state.Operations) - 1; index >= 0; index-- {
			if err := rollbackRestoreOperation(
				roots,
				state.Header.ID,
				state.Operations[index],
			); err != nil {
				return err
			}
		}
	}
	if err := cleanupRestoreTransaction(roots, state.Header.ID); err != nil {
		return err
	}
	return removeRestoreJournal(roots.project)
}

// RecoverInterruptedRestore rolls back an uncommitted restore journal or
// removes the artifacts of a restore that committed before cleanup completed.
// It is safe to call during daemon startup before project verification.
func (m *Manager) RecoverInterruptedRestore() error {
	if m == nil || m.projectDir == "" {
		return fmt.Errorf("backup manager project directory is required")
	}
	return recoverRestoreTransaction(m.projectDir)
}

func loadRestoreJournal(
	projectRoot *os.Root,
	expectedProjectPath string,
) (*restoreJournalState, bool, error) {
	before, err := projectRoot.Lstat(restoreJournalName)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, false, fmt.Errorf("restore journal must be a regular file")
	}
	if before.Mode().Perm()&0o022 != 0 {
		return nil, false, fmt.Errorf("restore journal must not be group/world writable")
	}
	if !securefs.OwnedBy(before, os.Geteuid()) {
		return nil, false, fmt.Errorf(
			"restore journal must be owned by the recovering process identity",
		)
	}
	if before.Size() < 1 || before.Size() > maxRestoreJournalSize {
		return nil, false, fmt.Errorf(
			"restore journal size must be between 1 and %d bytes",
			maxRestoreJournalSize,
		)
	}
	file, err := projectRoot.Open(restoreJournalName)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, false, fmt.Errorf("restore journal changed while it was opened")
	}

	decoder := json.NewDecoder(io.LimitReader(file, before.Size()+1))
	decoder.DisallowUnknownFields()
	state := &restoreJournalState{}
	operationIndex := make(map[string]*restoreJournalOperation)
	maxRecords := maxRestoreEntries*3 + 2
	for recordNumber := 0; ; recordNumber++ {
		if recordNumber > maxRecords {
			return nil, false, fmt.Errorf("restore journal has too many records")
		}
		var record restoreJournalRecord
		err := decoder.Decode(&record)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, fmt.Errorf("decode restore journal: %w", err)
		}
		if state.Committed {
			return nil, false, fmt.Errorf("restore journal contains records after commit")
		}
		if recordNumber == 0 {
			header, err := validateRestoreJournalHeader(record, expectedProjectPath)
			if err != nil {
				return nil, false, err
			}
			state.Header = header
			continue
		}
		key := string(record.Root) + "\x00" + record.Target
		switch record.Event {
		case restoreEventBegin:
			if err := validateRestoreJournalOperation(record); err != nil {
				return nil, false, err
			}
			if _, duplicate := operationIndex[key]; duplicate {
				return nil, false, fmt.Errorf("duplicate restore journal operation")
			}
			operation := &restoreJournalOperation{
				Root:        record.Root,
				Target:      record.Target,
				Existed:     record.Existed,
				CreatedDirs: append([]string(nil), record.CreatedDirs...),
			}
			operationIndex[key] = operation
			state.Operations = append(state.Operations, operation)
		case restoreEventBackedUp:
			if err := validateRestoreJournalProgress(record); err != nil {
				return nil, false, err
			}
			operation, ok := operationIndex[key]
			if !ok || !operation.Existed || operation.BackedUp {
				return nil, false, fmt.Errorf("invalid backed_up restore journal event")
			}
			operation.BackedUp = true
		case restoreEventPromoted:
			if err := validateRestoreJournalProgress(record); err != nil {
				return nil, false, err
			}
			operation, ok := operationIndex[key]
			if !ok || operation.Promoted ||
				(operation.Existed && !operation.BackedUp) {
				return nil, false, fmt.Errorf("invalid promoted restore journal event")
			}
			operation.Promoted = true
		case restoreEventCommit:
			if record.Version != 0 ||
				record.ID != "" ||
				record.ProjectPath != "" ||
				record.ConfigPath != "" ||
				record.SecretsPath != "" ||
				record.Root != "" ||
				record.Target != "" ||
				record.Existed ||
				len(record.CreatedDirs) != 0 {
				return nil, false, fmt.Errorf("invalid commit restore journal event")
			}
			state.Committed = true
		default:
			return nil, false, fmt.Errorf("unknown restore journal event %q", record.Event)
		}
	}
	if state.Header.ID == "" {
		return nil, false, fmt.Errorf("restore journal is empty")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if after.Size() != before.Size() || !os.SameFile(before, after) {
		return nil, false, fmt.Errorf("restore journal changed while it was read")
	}
	return state, true, nil
}

func validateRestoreJournalHeader(
	record restoreJournalRecord,
	expectedProjectPath string,
) (restoreJournalHeader, error) {
	if record.Event != restoreEventHeader ||
		record.Version != restoreJournalVersion ||
		record.Root != "" ||
		record.Target != "" ||
		record.Existed ||
		len(record.CreatedDirs) != 0 {
		return restoreJournalHeader{}, fmt.Errorf("invalid restore journal header")
	}
	if !validRestoreTransactionID(record.ID) {
		return restoreJournalHeader{}, fmt.Errorf("invalid restore transaction ID")
	}
	header := restoreJournalHeader{
		ID:          record.ID,
		ProjectPath: filepath.Clean(record.ProjectPath),
		ConfigPath:  filepath.Clean(record.ConfigPath),
		SecretsPath: filepath.Clean(record.SecretsPath),
	}
	if header.ProjectPath != record.ProjectPath ||
		header.ConfigPath != record.ConfigPath ||
		header.SecretsPath != record.SecretsPath {
		return restoreJournalHeader{}, fmt.Errorf("restore journal roots are not canonical")
	}
	for label, value := range map[string]string{
		"project": header.ProjectPath,
		"config":  header.ConfigPath,
		"secrets": header.SecretsPath,
	} {
		if !filepath.IsAbs(value) || filepath.Dir(value) == value {
			return restoreJournalHeader{}, fmt.Errorf(
				"restore journal %s root is invalid",
				label,
			)
		}
	}
	expected, err := filepath.Abs(expectedProjectPath)
	if err != nil {
		return restoreJournalHeader{}, err
	}
	if header.ProjectPath != filepath.Clean(expected) {
		return restoreJournalHeader{}, fmt.Errorf("restore journal belongs to another project")
	}
	if header.ConfigPath == header.ProjectPath ||
		header.SecretsPath == header.ProjectPath ||
		pathWithin(header.ConfigPath, header.ProjectPath) ||
		pathWithin(header.SecretsPath, header.ProjectPath) ||
		header.ConfigPath == header.SecretsPath ||
		pathsOverlap(header.ConfigPath, header.SecretsPath) {
		return restoreJournalHeader{}, fmt.Errorf("restore journal roots are invalid")
	}
	return header, nil
}

func validateRestoreJournalOperation(record restoreJournalRecord) error {
	if record.Event != restoreEventBegin ||
		record.Version != 0 ||
		record.ID != "" ||
		record.ProjectPath != "" ||
		record.ConfigPath != "" ||
		record.SecretsPath != "" {
		return fmt.Errorf("invalid begin restore journal event")
	}
	if _, err := validateRestoreRootKind(record.Root); err != nil {
		return err
	}
	if err := validateRestoreRelativePath(record.Target); err != nil {
		return err
	}
	parent := filepath.Dir(record.Target)
	previous := ""
	for _, directory := range record.CreatedDirs {
		if err := validateRestoreRelativePath(directory); err != nil {
			return err
		}
		relative, err := filepath.Rel(directory, parent)
		if err != nil || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("journal directory is not a target ancestor")
		}
		if previous != "" && filepath.Dir(directory) != previous {
			return fmt.Errorf("journal directories are not ordered ancestors")
		}
		previous = directory
	}
	return nil
}

func validateRestoreJournalProgress(record restoreJournalRecord) error {
	if (record.Event != restoreEventBackedUp &&
		record.Event != restoreEventPromoted) ||
		record.Version != 0 ||
		record.ID != "" ||
		record.ProjectPath != "" ||
		record.ConfigPath != "" ||
		record.SecretsPath != "" ||
		record.Existed ||
		len(record.CreatedDirs) != 0 {
		return fmt.Errorf("invalid %s restore journal event", record.Event)
	}
	if _, err := validateRestoreRootKind(record.Root); err != nil {
		return err
	}
	return validateRestoreRelativePath(record.Target)
}

func rollbackRestoreOperation(
	roots *restoreRoots,
	transactionID string,
	operation *restoreJournalOperation,
) error {
	root, _, err := roots.rootForKind(operation.Root)
	if err != nil {
		return err
	}
	stageName := restoreStageName(transactionID, operation.Target)
	rollbackName := restoreRollbackName(transactionID, operation.Target)
	stageParent, stageBase, stageParentExists, err := openRestoreParentOptional(
		root,
		stageName,
	)
	if err != nil {
		return err
	}
	if stageParentExists {
		defer stageParent.Close()
	}
	rollbackParent, rollbackBase, rollbackParentExists, err := openRestoreParentOptional(
		root,
		rollbackName,
	)
	if err != nil {
		return err
	}
	if rollbackParentExists {
		defer rollbackParent.Close()
	}
	var rollbackInfo fs.FileInfo
	var rollbackExists bool
	if rollbackParentExists {
		rollbackInfo, rollbackExists, err = lstatOptional(rollbackParent, rollbackBase)
		if err != nil {
			return err
		}
		if rollbackExists &&
			(rollbackInfo.Mode()&os.ModeSymlink != 0 ||
				!rollbackInfo.Mode().IsRegular()) {
			return fmt.Errorf("restore rollback file %q is not regular", operation.Target)
		}
	}

	if operation.Existed {
		if rollbackExists {
			targetParent, targetBase, targetParentExists, err := openRestoreParentOptional(
				root,
				operation.Target,
			)
			if err != nil {
				return err
			}
			if !targetParentExists {
				return fmt.Errorf("restore target parent for %q is missing", operation.Target)
			}
			defer targetParent.Close()
			if err := removeRegularTargetIfPresent(targetParent, targetBase); err != nil {
				return err
			}
			if err := securefs.RenameBaseAt(
				rollbackParent,
				rollbackBase,
				targetParent,
				targetBase,
			); err != nil {
				return err
			}
			if err := syncRootDirectory(rollbackParent, "."); err != nil {
				return err
			}
			if err := syncRootDirectory(targetParent, "."); err != nil {
				return err
			}
		} else if operation.BackedUp || operation.Promoted {
			return fmt.Errorf("restore rollback file for %q is missing", operation.Target)
		} else {
			targetParent, targetBase, targetParentExists, err := openRestoreParentOptional(
				root,
				operation.Target,
			)
			if err != nil {
				return err
			}
			if !targetParentExists {
				return fmt.Errorf("original restore target %q is missing", operation.Target)
			}
			defer targetParent.Close()
			info, exists, err := lstatOptional(targetParent, targetBase)
			if err != nil {
				return err
			}
			if !exists || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("original restore target %q is missing", operation.Target)
			}
		}
	} else {
		stageExists := false
		if stageParentExists {
			if _, stageExists, err = lstatOptional(stageParent, stageBase); err != nil {
				return err
			}
		}
		if operation.Promoted || !stageExists {
			targetParent, targetBase, targetParentExists, err := openRestoreParentOptional(
				root,
				operation.Target,
			)
			if err != nil {
				return err
			}
			if !targetParentExists {
				return fmt.Errorf("restore target parent for %q is missing", operation.Target)
			}
			defer targetParent.Close()
			if err := removeRegularTargetIfPresent(targetParent, targetBase); err != nil {
				return err
			}
			if err := syncRootDirectory(targetParent, "."); err != nil {
				return err
			}
		}
	}
	for index := len(operation.CreatedDirs) - 1; index >= 0; index-- {
		directory := operation.CreatedDirs[index]
		parent, base, exists, err := openRestoreParentOptional(root, directory)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		info, directoryExists, err := lstatOptional(parent, base)
		if err != nil {
			_ = parent.Close()
			return err
		}
		if !directoryExists {
			_ = parent.Close()
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			_ = parent.Close()
			return fmt.Errorf("rollback directory %q changed type", directory)
		}
		if err := parent.Remove(base); err != nil {
			_ = parent.Close()
			return fmt.Errorf("remove rollback directory %q: %w", directory, err)
		}
		if err := syncRootDirectory(parent, "."); err != nil {
			_ = parent.Close()
			return err
		}
		if err := parent.Close(); err != nil {
			return err
		}
	}
	return nil
}

func openRestoreParentOptional(
	root *os.Root,
	target string,
) (*os.Root, string, bool, error) {
	if err := validateRestoreRelativePath(target); err != nil {
		return nil, "", false, err
	}
	parent, err := securefs.OpenPinnedDirectoryAt(
		root,
		filepath.Dir(target),
		false,
		0,
	)
	if errors.Is(err, os.ErrNotExist) {
		return nil, filepath.Base(target), false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	return parent, filepath.Base(target), true, nil
}

func cleanupRestoreTransaction(roots *restoreRoots, transactionID string) error {
	transactionName := restoreTransactionName(transactionID)
	for _, root := range []*os.Root{roots.project, roots.config, roots.secrets} {
		if err := root.RemoveAll(transactionName); err != nil {
			return err
		}
		if err := syncRootDirectory(root, "."); err != nil {
			return err
		}
	}
	return nil
}

func removeRestoreJournal(projectRoot *os.Root) error {
	info, exists, err := lstatOptional(projectRoot, restoreJournalName)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("restore journal changed before cleanup")
	}
	if err := projectRoot.Remove(restoreJournalName); err != nil {
		return err
	}
	return syncRootDirectory(projectRoot, ".")
}

func removeRegularTargetIfPresent(parent *os.Root, targetBase string) error {
	info, exists, err := lstatOptional(parent, targetBase)
	if err != nil || !exists {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("restore target %q changed to a non-regular file", targetBase)
	}
	return parent.Remove(targetBase)
}

func lstatOptional(root *os.Root, name string) (fs.FileInfo, bool, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return info, true, nil
}

func (r *restoreRoots) destinationRecord(
	archiveName string,
) (restoreRootKind, *os.Root, string, bool) {
	switch {
	case strings.HasPrefix(archiveName, "configs/"):
		return restoreRootConfig,
			r.config,
			filepath.FromSlash(strings.TrimPrefix(archiveName, "configs/")),
			false
	case strings.HasPrefix(archiveName, "secrets/"):
		return restoreRootSecrets,
			r.secrets,
			filepath.FromSlash(strings.TrimPrefix(archiveName, "secrets/")),
			true
	default:
		return restoreRootProject,
			r.project,
			filepath.FromSlash(archiveName),
			archiveName == ".env"
	}
}

func (r *restoreRoots) rootForKind(
	kind restoreRootKind,
) (*os.Root, string, error) {
	switch kind {
	case restoreRootProject:
		return r.project, r.projectPath, nil
	case restoreRootConfig:
		return r.config, r.configPath, nil
	case restoreRootSecrets:
		return r.secrets, r.secretsPath, nil
	default:
		return nil, "", fmt.Errorf("unknown restore root %q", kind)
	}
}

func validateRestoreRootKind(kind restoreRootKind) (restoreRootKind, error) {
	switch kind {
	case restoreRootProject, restoreRootConfig, restoreRootSecrets:
		return kind, nil
	default:
		return "", fmt.Errorf("invalid restore root %q", kind)
	}
}

func validateRestoreRelativePath(name string) error {
	if name == "" || name == "." || filepath.IsAbs(name) ||
		!filepath.IsLocal(name) || filepath.Clean(name) != name ||
		len(name) > maxArchivePathLength {
		return fmt.Errorf("invalid restore-relative path %q", name)
	}
	return nil
}

func syncRootDirectory(root *os.Root, name string) error {
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", name)
	}
	return directory.Sync()
}

func callRestoreHook(
	hook func(phase, target string) error,
	phase, target string,
) error {
	if hook == nil {
		return nil
	}
	if err := hook(phase, target); err != nil {
		return fmt.Errorf("restore hook %s for %q: %w", phase, target, err)
	}
	return nil
}

func newRestoreTransactionID() (string, error) {
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return hex.EncodeToString(random), nil
}

func validRestoreTransactionID(value string) bool {
	if len(value) != 48 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 24
}

func restoreTransactionName(transactionID string) string {
	return restoreTransactionTag + transactionID
}

func restoreStageName(transactionID, target string) string {
	return filepath.Join(restoreTransactionName(transactionID), "stage", target)
}

func restoreRollbackName(transactionID, target string) string {
	return filepath.Join(restoreTransactionName(transactionID), "rollback", target)
}
