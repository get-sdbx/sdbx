package securefs

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestWriteFileAtomicReplacesContentAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "lock.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o666); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(path, []byte("new"), 0o755, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("content = %q, want new", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}

func TestWriteFileAtomicDoesNotFollowTargetSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on Windows")
	}
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	target := filepath.Join(root, "target")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, target); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(target, []byte("replacement"), 0o755, 0o600); err != nil {
		t.Fatal(err)
	}
	victimData, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(victimData) != "keep" {
		t.Fatalf("symlink victim changed to %q", victimData)
	}
	targetInfo, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if targetInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatal("target remained a symlink")
	}
}

func TestWriteFileAtomicRejectsSpecialModeBits(t *testing.T) {
	err := WriteFileAtomic(
		filepath.Join(t.TempDir(), "state"),
		[]byte("data"),
		0o755,
		os.ModeSetuid|0o600,
	)
	if err == nil {
		t.Fatal("special mode bits were accepted")
	}
}

func TestWriteReaderAtomicRequiresExactBoundedSize(t *testing.T) {
	for _, test := range []struct {
		name     string
		data     string
		expected int64
	}{
		{name: "short", data: "abc", expected: 4},
		{name: "long", data: "abcde", expected: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "target")
			err := WriteReaderAtomic(
				target,
				bytes.NewBufferString(test.data),
				test.expected,
				0o700,
				0o600,
			)
			if err == nil {
				t.Fatal("size mismatch was accepted")
			}
			if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
				t.Fatalf("target exists after failed write: %v", statErr)
			}
		})
	}

	target := filepath.Join(t.TempDir(), "target")
	if err := WriteReaderAtomic(
		target,
		bytes.NewBufferString("exact"),
		5,
		0o700,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureDirRepairsModeAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state")
	if err := os.Mkdir(path, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("mode = %o, want 700", got)
	}

	if runtime.GOOS == "windows" {
		return
	}
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(link, 0o700); err == nil {
		t.Fatal("EnsureDir accepted a symlink")
	}
}

func TestEnsureDirPinsFinalDirectoryBeforeMetadataRepair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	root := t.TempDir()
	target := filepath.Join(root, "state")
	displaced := filepath.Join(root, "state-displaced")
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outside, 0o755); err != nil {
		t.Fatal(err)
	}

	var hookErr error
	err := ensureDir(target, 0o700, func() {
		if renameErr := os.Rename(target, displaced); renameErr != nil {
			hookErr = renameErr
			return
		}
		hookErr = os.Symlink(outside, target)
	})
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if err == nil || !strings.Contains(err.Error(), "changed while metadata was applied") {
		t.Fatalf("ensureDir() error = %v, want pathname replacement rejection", err)
	}
	outsideInfo, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if outsideInfo.Mode().Perm() != 0o755 {
		t.Fatalf("outside directory mode = %o, want unchanged 755", outsideInfo.Mode().Perm())
	}
	displacedInfo, err := os.Stat(displaced)
	if err != nil {
		t.Fatal(err)
	}
	if displacedInfo.Mode().Perm() != 0o700 {
		t.Fatalf("pinned directory mode = %o, want 700", displacedInfo.Mode().Perm())
	}
}

func TestEnsureDirRefusesFilesystemRoot(t *testing.T) {
	root := string(filepath.Separator)
	if runtime.GOOS == "windows" {
		volume := filepath.VolumeName(t.TempDir())
		root = volume + string(filepath.Separator)
	}
	if err := EnsureDir(root, 0o755); err == nil {
		t.Fatal("EnsureDir accepted a filesystem root")
	}
}

func TestWriteFileAtomicPreserveDirDoesNotWeakenParent(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "config.yaml")
	if err := WriteFileAtomicPreserveDir(path, []byte("ok"), 0o755, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("parent mode = %o, want preserved 700", got)
	}
}

func TestApplyReplacementOwnershipRejectsInvalidInput(t *testing.T) {
	if err := ApplyReplacementOwnership(nil, filepath.Join(t.TempDir(), "state")); err == nil {
		t.Fatal("nil replacement file was accepted")
	}
	file, err := os.CreateTemp(t.TempDir(), "replacement-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := ApplyReplacementOwnership(file, ""); err == nil {
		t.Fatal("empty replacement target was accepted")
	}
	if err := InheritFileOwnership(nil, nil); err == nil {
		t.Fatal("nil ownership target was accepted")
	}
	if err := InheritRootPathOwnership(nil, "", nil); err == nil {
		t.Fatal("nil ownership root was accepted")
	}
}

func TestReadRegularFileRejectsSymlinksAndOversizedFiles(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadRegularFile(regular, 5); err != nil || string(data) != "12345" {
		t.Fatalf("ReadRegularFile() = %q, %v", data, err)
	}
	if _, err := ReadRegularFile(regular, 4); err == nil {
		t.Fatal("oversized file was accepted")
	}

	if runtime.GOOS == "windows" {
		return
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(link, 5); err == nil {
		t.Fatal("symlink was accepted")
	}
}

func TestReadRegularFileAtRejectsRootAndFileSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on Windows")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "secrets")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, "credential"),
		[]byte("synthetic"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	data, err := ReadRegularFileAt(root, "credential", 32)
	if err != nil || string(data) != "synthetic" {
		t.Fatalf("ReadRegularFileAt() = %q, %v", data, err)
	}

	fileLink := filepath.Join(root, "credential-link")
	if err := os.Symlink("credential", fileLink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFileAt(root, "credential-link", 32); err == nil {
		t.Fatal("root-relative read accepted a file symlink")
	}

	rootLink := filepath.Join(parent, "secrets-link")
	if err := os.Symlink(root, rootLink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFileAt(rootLink, "credential", 32); err == nil {
		t.Fatal("root-relative read accepted a root symlink")
	}
}

func TestWriteFileAtomicOwnedAtRejectsSymlinkedParents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	for _, test := range []struct {
		name   string
		target func(parent, outside string) string
	}{
		{
			name: "absolute",
			target: func(_ string, outside string) string {
				return outside
			},
		},
		{
			name: "relative",
			target: func(_ string, _ string) string {
				return filepath.Join("..", "outside")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "managed")
			outside := filepath.Join(parent, "outside")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(outside, "config.xml")
			if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(
				test.target(parent, outside),
				filepath.Join(root, "sonarr"),
			); err != nil {
				t.Fatal(err)
			}

			err := WriteFileAtomicOwnedAt(
				root,
				filepath.Join("sonarr", "config.xml"),
				[]byte("replacement"),
				0o755,
				0o600,
				-1,
				-1,
			)
			if err == nil {
				t.Fatal("root-relative atomic write accepted a symlinked parent")
			}
			body, readErr := os.ReadFile(victim)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(body) != "keep" {
				t.Fatalf("outside victim changed to %q", body)
			}
			info, statErr := os.Stat(victim)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if info.Mode().Perm() != 0o644 {
				t.Fatalf("outside victim mode changed to %o", info.Mode().Perm())
			}
		})
	}
}

func TestRepairAndChownAtRejectSymlinkedTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	for _, linkTarget := range []string{"absolute", "relative"} {
		t.Run(linkTarget, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "managed")
			outside := filepath.Join(parent, "outside")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(outside, "config.xml")
			if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
				t.Fatal(err)
			}
			target := outside
			if linkTarget == "relative" {
				target = filepath.Join("..", "outside")
			}
			link := filepath.Join(root, "redirect")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(outside)
			if err != nil {
				t.Fatal(err)
			}

			if err := RepairRegularFileMetadataAt(
				root,
				filepath.Join("redirect", "config.xml"),
				0o600,
				12345,
				12346,
			); err == nil {
				t.Fatal("metadata repair accepted a symlinked parent")
			}
			if err := ChownRealDirectoryAt(
				root,
				link,
				12345,
				12346,
			); err == nil {
				t.Fatal("directory chown accepted a symlinked target")
			}

			victimInfo, err := os.Stat(victim)
			if err != nil {
				t.Fatal(err)
			}
			if victimInfo.Mode().Perm() != 0o644 {
				t.Fatalf("outside file mode changed to %o", victimInfo.Mode().Perm())
			}
			after, err := os.Stat(outside)
			if err != nil {
				t.Fatal(err)
			}
			beforeOwnership := ownershipFromInfo(before)
			afterOwnership := ownershipFromInfo(after)
			if beforeOwnership != afterOwnership {
				t.Fatalf(
					"outside directory ownership changed: before=%+v after=%+v",
					beforeOwnership,
					afterOwnership,
				)
			}
		})
	}
}

func TestRejectSymlinkTraversalChecksEveryComponentBelowTrustedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(outside, "credentials"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "redirect")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(link, "credentials")
	if err := RejectSymlinkTraversal(root, target); err == nil {
		t.Fatal("intermediate symlink traversal was accepted")
	}

	missing := filepath.Join(root, "future", "credentials")
	if err := RejectSymlinkTraversal(root, missing); err != nil {
		t.Fatalf("safe missing path rejected: %v", err)
	}
	if err := RejectSymlinkTraversal(root, outside); err == nil {
		t.Fatal("path outside trusted root was accepted")
	}
}

func TestRootWritesPreserveExistingFileAndParentOwnership(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires a Linux root test environment")
	}
	root := t.TempDir()
	const (
		testUID = 12345
		testGID = 12346
	)
	if err := os.Chown(root, testUID, testGID); err != nil {
		t.Fatal(err)
	}

	nested := filepath.Join(root, "managed", "nested")
	if err := EnsureDir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	assertOwnership(t, filepath.Join(root, "managed"), testUID, testGID)
	assertOwnership(t, nested, testUID, testGID)

	existing := filepath.Join(nested, "existing")
	if err := os.WriteFile(existing, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(existing, testUID+1, testGID+1); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomicPreserveDir(existing, []byte("new"), 0o700, 0o600); err != nil {
		t.Fatal(err)
	}
	assertOwnership(t, existing, testUID+1, testGID+1)

	created := filepath.Join(nested, "created")
	if err := WriteFileAtomicPreserveDir(created, []byte("new"), 0o700, 0o600); err != nil {
		t.Fatal(err)
	}
	assertOwnership(t, created, testUID, testGID)

	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer rootHandle.Close()
	nestedInfo, err := os.Stat(nested)
	if err != nil {
		t.Fatal(err)
	}
	if err := rootHandle.Mkdir("root-owned-before-inherit", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := InheritRootPathOwnership(
		rootHandle,
		"root-owned-before-inherit",
		nestedInfo,
	); err != nil {
		t.Fatal(err)
	}
	assertOwnership(
		t,
		filepath.Join(root, "root-owned-before-inherit"),
		testUID,
		testGID,
	)
}

func assertOwnership(t *testing.T, path string, uid, gid int) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s has no syscall.Stat_t", path)
	}
	if int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Fatalf(
			"%s ownership = %d:%d, want %d:%d",
			path,
			stat.Uid,
			stat.Gid,
			uid,
			gid,
		)
	}
}

func TestWriteFileAtomicAtRejectsSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "notices")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := WriteFileAtomicAt(root, "notices", []byte("replace"), 0o644); err == nil {
		t.Fatal("WriteFileAtomicAt accepted a symlink target")
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("outside target = %q, want keep", data)
	}
}
