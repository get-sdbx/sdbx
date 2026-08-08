package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"filippo.io/age"
)

var (
	testEncryptOptions = EncryptOptions{Passphrase: []byte("correct horse battery staple")}
	testDecryptOptions = DecryptOptions{Passphrase: []byte("correct horse battery staple")}
)

func TestValidateBackupNameRejectsTerminalControls(t *testing.T) {
	if err := ValidateBackupName("safe.tar.gz.age"); err != nil {
		t.Fatalf("safe backup name rejected: %v", err)
	}
	for _, name := range []string{
		"escape-\x1b[2J.tar.gz.age",
		"carriage-\rreturn.tar.gz.age",
		"line-\nfeed.tar.gz.age",
		"bidi-\u202Eevil.tar.gz.age",
	} {
		if err := ValidateBackupName(name); err == nil {
			t.Fatalf("unsafe backup name accepted: %q", name)
		}
	}
}

func TestListSkipsBackupNamesWithTerminalControls(t *testing.T) {
	projectDir := t.TempDir()
	backupDir := filepath.Join(projectDir, "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"safe.tar.gz.age",
		"escape-\x1b[2J.tar.gz.age",
		"carriage-\rreturn.tar.gz.age",
		"line-\nfeed.tar.gz.age",
		"bidi-\u202Eevil.tar.gz.age",
	} {
		if err := os.WriteFile(filepath.Join(backupDir, name), []byte("encrypted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	backups, err := NewManager(projectDir).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 || backups[0].Name != "safe.tar.gz.age" {
		t.Fatalf("discovered backups = %+v, want only the safe name", backups)
	}
}

func TestEncryptedPassphraseRoundTrip(t *testing.T) {
	projectDir := seedBackupProject(t)
	manager := NewManager(projectDir)
	backup, err := manager.Create(context.Background(), testEncryptOptions)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if !strings.HasSuffix(backup.Name, backupSuffix) {
		t.Fatalf("backup name = %q, want encrypted suffix", backup.Name)
	}
	info, err := os.Stat(backup.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %o, want 600", info.Mode().Perm())
	}
	encrypted, err := os.ReadFile(backup.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("TOP_SECRET_CANARY")) {
		t.Fatal("encrypted backup contains plaintext secret canary")
	}

	if err := os.RemoveAll(filepath.Join(projectDir, "configs")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(projectDir, "secrets")); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), backup.Name, testDecryptOptions); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}
	assertFileContent(t, filepath.Join(projectDir, "configs", "app", "config.yml"), "enabled: true\n")
	assertFileContent(t, filepath.Join(projectDir, "secrets", "token.txt"), "TOP_SECRET_CANARY\n")
	secretInfo, err := os.Stat(filepath.Join(projectDir, "secrets", "token.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if secretInfo.Mode().Perm() != 0o600 {
		t.Fatalf("restored secret mode = %o, want 600", secretInfo.Mode().Perm())
	}
	for path, expectedMode := range map[string]os.FileMode{
		filepath.Join(projectDir, "configs"):        0o755,
		filepath.Join(projectDir, "configs", "app"): 0o755,
		filepath.Join(projectDir, "secrets"):        0o700,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != expectedMode {
			t.Fatalf(
				"restored directory %s mode = %o, want %o",
				path,
				info.Mode().Perm(),
				expectedMode,
			)
		}
	}
}

func TestEncryptedRecipientRoundTripWithoutStoredPrivateIdentity(t *testing.T) {
	projectDir := seedBackupProject(t)
	manager := NewManager(projectDir)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	backup, err := manager.Create(context.Background(), EncryptOptions{
		Recipient: identity.Recipient().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(identityPath, []byte(identity.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(projectDir, "configs")); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), backup.Name, DecryptOptions{
		IdentityFile: identityPath,
	}); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, filepath.Join(projectDir, "configs", "app", "config.yml"), "enabled: true\n")
}

func TestCreateRequiresExactlyOneEncryptionMode(t *testing.T) {
	manager := NewManager(seedBackupProject(t))
	for _, options := range []EncryptOptions{
		{},
		{Recipient: "age1invalid", Passphrase: []byte("also-set")},
	} {
		if _, err := manager.Create(context.Background(), options); err == nil {
			t.Fatalf("Create accepted options %#v", options)
		}
	}
}

func TestRootCreatePreservesProjectOwnerOnBackup(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires a Linux root test environment")
	}
	projectDir := seedBackupProject(t)
	const (
		testUID = 12345
		testGID = 12346
	)
	if err := os.Chown(projectDir, testUID, testGID); err != nil {
		t.Fatal(err)
	}

	created, err := NewManager(projectDir).Create(
		context.Background(),
		testEncryptOptions,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertFileOwnership(t, filepath.Join(projectDir, "backups"), testUID, testGID)
	assertFileOwnership(t, created.Path, testUID, testGID)
}

func TestEncryptedBackupIncludesPrivateRuntimeEnvironment(t *testing.T) {
	projectDir := seedBackupProject(t)
	environmentPath := filepath.Join(projectDir, ".env")
	if err := os.WriteFile(
		environmentPath,
		[]byte("PRIVATE_RUNTIME_CANARY=present\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(projectDir)
	created, err := manager.Create(context.Background(), testEncryptOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(environmentPath, []byte("PRIVATE_RUNTIME_CANARY=changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), created.Name, testDecryptOptions); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, environmentPath, "PRIVATE_RUNTIME_CANARY=present\n")
	info, err := os.Stat(environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("restored .env mode = %o, want 600", info.Mode().Perm())
	}
}

func TestRestoreRejectsWrongPassphraseBeforeWriting(t *testing.T) {
	projectDir := seedBackupProject(t)
	manager := NewManager(projectDir)
	backup, err := manager.Create(context.Background(), testEncryptOptions)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(projectDir, "configs", "app", "config.yml")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err = manager.Restore(context.Background(), backup.Name, DecryptOptions{
		Passphrase: []byte("wrong passphrase"),
	})
	if err == nil {
		t.Fatal("Restore succeeded with wrong passphrase")
	}
	assertFileContent(t, target, "keep\n")
}

func TestRestoreRollsBackCompleteManagedSetOnPromotionFailure(t *testing.T) {
	projectDir := seedBackupProject(t)
	manager := NewManager(projectDir)
	created, err := manager.Create(context.Background(), testEncryptOptions)
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]string{
		filepath.Join(projectDir, ".sdbx.yaml"):                   "config_path: ./configs\nsecrets_path: ./secrets\nkeep: current\n",
		filepath.Join(projectDir, "compose.yaml"):                 "name: keep-current\n",
		filepath.Join(projectDir, "secrets", "token.txt"):         "KEEP_CURRENT_SECRET\n",
		filepath.Join(projectDir, "configs", "app", "config.yml"): "enabled: false\n",
	}
	for filePath, content := range before {
		if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	promotions := 0
	manager.restoreHook = func(phase, _ string) error {
		if phase != "after-promote" {
			return nil
		}
		promotions++
		if promotions == 2 {
			return errors.New("injected promotion failure")
		}
		return nil
	}
	err = manager.Restore(context.Background(), created.Name, testDecryptOptions)
	if err == nil || !strings.Contains(err.Error(), "injected promotion failure") {
		t.Fatalf("Restore error = %v, want injected failure", err)
	}
	for filePath, content := range before {
		assertFileContent(t, filePath, content)
	}
	assertNoRestoreTransactionArtifacts(t, projectDir)
}

func TestRestoreRollsBackWhenPostPromotionValidationFails(t *testing.T) {
	projectDir := seedBackupProject(t)
	manager := NewManager(projectDir)
	created, err := manager.Create(context.Background(), testEncryptOptions)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(projectDir, "configs", "app", "config.yml")
	secretPath := filepath.Join(projectDir, "secrets", "token.txt")
	if err := os.WriteFile(configPath, []byte("keep-config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte("keep-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	validationCalled := false
	err = manager.RestoreWithHooks(
		context.Background(),
		created.Name,
		testDecryptOptions,
		RestoreHooks{
			Validate: func(context.Context) error {
				validationCalled = true
				assertFileContent(t, configPath, "enabled: true\n")
				assertFileContent(t, secretPath, "TOP_SECRET_CANARY\n")
				return errors.New("restored project is inconsistent")
			},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "restored project is inconsistent") {
		t.Fatalf("RestoreWithHooks error = %v, want validation failure", err)
	}
	if !validationCalled {
		t.Fatal("post-promotion validation was not called")
	}
	assertFileContent(t, configPath, "keep-config\n")
	assertFileContent(t, secretPath, "keep-secret\n")
	assertNoRestoreTransactionArtifacts(t, projectDir)
}

func TestRestoreRecoversInterruptedCompleteSetBeforeRetry(t *testing.T) {
	projectDir := seedBackupProject(t)
	manager := NewManager(projectDir)
	created, err := manager.Create(context.Background(), testEncryptOptions)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(projectDir, "configs", "app", "config.yml")
	secretPath := filepath.Join(projectDir, "secrets", "token.txt")
	if err := os.WriteFile(configPath, []byte("keep-config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte("keep-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	promotions := 0
	manager.restoreHook = func(phase, _ string) error {
		if phase == "after-promote" {
			promotions++
		}
		if promotions == 2 && phase == "after-promote" {
			return errSimulatedRestoreCrash
		}
		return nil
	}
	err = manager.Restore(context.Background(), created.Name, testDecryptOptions)
	if !errors.Is(err, errSimulatedRestoreCrash) {
		t.Fatalf("Restore error = %v, want simulated interruption", err)
	}
	if _, err := os.Lstat(filepath.Join(projectDir, restoreJournalName)); err != nil {
		t.Fatalf("interrupted restore did not retain its journal: %v", err)
	}
	if err := recoverRestoreTransaction(projectDir); err != nil {
		t.Fatalf("recoverRestoreTransaction failed: %v", err)
	}
	assertFileContent(t, configPath, "keep-config\n")
	assertFileContent(t, secretPath, "keep-secret\n")
	assertNoRestoreTransactionArtifacts(t, projectDir)

	manager.restoreHook = nil
	if err := manager.Restore(context.Background(), created.Name, testDecryptOptions); err != nil {
		t.Fatalf("retry after recovery failed: %v", err)
	}
	assertFileContent(t, configPath, "enabled: true\n")
	assertFileContent(t, secretPath, "TOP_SECRET_CANARY\n")
	assertNoRestoreTransactionArtifacts(t, projectDir)
}

func TestRecoverInterruptedRestoreRejectsUnconfiguredManager(t *testing.T) {
	if err := (*Manager)(nil).RecoverInterruptedRestore(); err == nil {
		t.Fatal("nil manager recovery was accepted")
	}
	if err := (&Manager{}).RecoverInterruptedRestore(); err == nil {
		t.Fatal("empty project recovery was accepted")
	}
}

func TestRootRestorePreservesExistingAndInheritedOwnership(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires a Linux root test environment")
	}
	projectDir := seedBackupProject(t)
	const (
		projectUID = 12345
		projectGID = 12346
		targetUID  = 12347
		targetGID  = 12348
	)
	for _, directory := range []string{
		projectDir,
		filepath.Join(projectDir, "configs"),
		filepath.Join(projectDir, "configs", "app"),
		filepath.Join(projectDir, "secrets"),
	} {
		if err := os.Chown(directory, projectUID, projectGID); err != nil {
			t.Fatal(err)
		}
	}
	manager := NewManager(projectDir)
	created, err := manager.Create(context.Background(), testEncryptOptions)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(projectDir, "configs", "app", "config.yml")
	if err := os.Chown(configPath, targetUID, targetGID); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(projectDir, "secrets", "token.txt")
	if err := os.Remove(secretPath); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), created.Name, testDecryptOptions); err != nil {
		t.Fatal(err)
	}
	assertFileOwnership(t, configPath, targetUID, targetGID)
	assertFileOwnership(t, secretPath, projectUID, projectGID)
}

func TestRestoreRejectsPathTraversalBeforeWriting(t *testing.T) {
	projectDir := t.TempDir()
	manager := NewManager(projectDir)
	backupName := "malicious" + backupSuffix
	writeTestArchive(t, filepath.Join(prepareBackupDir(t, manager), backupName), []tarEntry{
		{name: "metadata.json", body: validMetadata(), mode: 0o600},
		{name: "configs/good.yml", body: []byte("must-not-write"), mode: 0o600},
		{name: "../escape.txt", body: []byte("owned"), mode: 0o600},
	})

	err := manager.Restore(context.Background(), backupName, testDecryptOptions)
	if err == nil {
		t.Fatal("Restore succeeded for path traversal archive")
	}
	for _, candidate := range []string{
		filepath.Join(projectDir, "configs", "good.yml"),
		filepath.Join(filepath.Dir(projectDir), "escape.txt"),
	} {
		if _, statErr := os.Stat(candidate); !os.IsNotExist(statErr) {
			t.Fatalf("preflight failure wrote %s, stat err=%v", candidate, statErr)
		}
	}
}

func TestRestoreRejectsDisallowedPathsDuplicatesAndSpecialTypes(t *testing.T) {
	tests := []struct {
		name    string
		entries []tarEntry
	}{
		{
			name: "arbitrary project path",
			entries: []tarEntry{
				{name: "metadata.json", body: validMetadata(), mode: 0o600},
				{name: ".git/config", body: []byte("owned"), mode: 0o600},
			},
		},
		{
			name: "duplicate",
			entries: []tarEntry{
				{name: "metadata.json", body: validMetadata(), mode: 0o600},
				{name: "configs/app.yml", body: []byte("one"), mode: 0o600},
				{name: "configs/app.yml", body: []byte("two"), mode: 0o600},
			},
		},
		{
			name: "symlink",
			entries: []tarEntry{
				{name: "metadata.json", body: validMetadata(), mode: 0o600},
				{name: "configs/link", mode: 0o600, entry: tar.TypeSymlink, linkName: "../../outside"},
			},
		},
		{
			name: "hard link",
			entries: []tarEntry{
				{name: "metadata.json", body: validMetadata(), mode: 0o600},
				{name: "configs/link", mode: 0o600, entry: tar.TypeLink, linkName: "compose.yaml"},
			},
		},
		{
			name: "unsafe mode",
			entries: []tarEntry{
				{name: "metadata.json", body: validMetadata(), mode: 0o600},
				{name: "configs/world-writable.yml", body: []byte("bad"), mode: 0o666},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projectDir := t.TempDir()
			manager := NewManager(projectDir)
			backupName := "bad" + backupSuffix
			writeTestArchive(t, filepath.Join(prepareBackupDir(t, manager), backupName), test.entries)
			if err := manager.Restore(context.Background(), backupName, testDecryptOptions); err == nil {
				t.Fatal("Restore accepted hostile archive")
			}
		})
	}
}

func TestRestoreRejectsTargetAndParentSymlinks(t *testing.T) {
	tests := []struct {
		name string
		link func(t *testing.T, projectDir, outside string)
	}{
		{
			name: "target symlink",
			link: func(t *testing.T, projectDir, outside string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(projectDir, "configs", "app"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(
					filepath.Join(outside, "config.yml"),
					filepath.Join(projectDir, "configs", "app", "config.yml"),
				); err != nil {
					t.Skipf("symlink unsupported: %v", err)
				}
			},
		},
		{
			name: "parent symlink",
			link: func(t *testing.T, projectDir, outside string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(projectDir, "configs"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(projectDir, "configs", "app")); err != nil {
					t.Skipf("symlink unsupported: %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projectDir := t.TempDir()
			outside := t.TempDir()
			outsideTarget := filepath.Join(outside, "config.yml")
			if err := os.WriteFile(outsideTarget, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			test.link(t, projectDir, outside)
			manager := NewManager(projectDir)
			backupName := "symlink" + backupSuffix
			writeTestArchive(t, filepath.Join(prepareBackupDir(t, manager), backupName), []tarEntry{
				{name: "metadata.json", body: validMetadata(), mode: 0o600},
				{name: "configs/app/config.yml", body: []byte("owned"), mode: 0o600},
			})
			if err := manager.Restore(context.Background(), backupName, testDecryptOptions); err == nil {
				t.Fatal("Restore accepted symlinked target")
			}
			assertFileContent(t, outsideTarget, "keep")
		})
	}
}

func TestCreateRejectsSymlinkedSourceInsteadOfSilentlyOmittingIt(t *testing.T) {
	projectDir := seedBackupProject(t)
	outside := filepath.Join(t.TempDir(), "outside-secret.txt")
	if err := os.WriteFile(outside, []byte("do-not-leak"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(projectDir, "secrets", "outside-secret.txt")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	manager := NewManager(projectDir)
	if _, err := manager.Create(context.Background(), testEncryptOptions); err == nil {
		t.Fatal("Create silently accepted a symlinked backup source")
	}
	entries, err := os.ReadDir(manager.backupDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed Create left backup artifacts: %#v", entries)
	}
}

func TestCreateOmitsSafeRelativeSymlinkAndUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets and POSIX symlinks are unavailable")
	}
	projectDir, err := os.MkdirTemp("/tmp", "sdbx-backup-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(projectDir); err != nil {
			t.Errorf("remove short backup fixture: %v", err)
		}
	})
	seedBackupProjectAt(t, projectDir)
	appRoot := filepath.Join(projectDir, "configs", "app")
	targetPath := filepath.Join(appRoot, "current.log")
	if err := os.WriteFile(targetPath, []byte("current\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(appRoot, "latest.log")
	if err := os.Symlink("current.log", linkPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	socketPath := filepath.Join(appRoot, "qbittorrent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("Unix socket unsupported: %v", err)
	}
	defer listener.Close()

	manager := NewManager(projectDir)
	created, err := manager.Create(context.Background(), testEncryptOptions)
	if err != nil {
		t.Fatal(err)
	}
	wantOmissions := map[string]string{
		"configs/app/latest.log":       "symlink",
		"configs/app/qbittorrent.sock": "unix_socket",
	}
	if len(created.Metadata.Omissions) != len(wantOmissions) {
		t.Fatalf("omissions = %#v", created.Metadata.Omissions)
	}
	for _, omission := range created.Metadata.Omissions {
		if wantOmissions[omission.Path] != omission.Type {
			t.Errorf("unexpected omission: %#v", omission)
		}
	}

	entries := decryptArchiveEntries(t, created.Path)
	for omitted := range wantOmissions {
		if _, exists := entries[omitted]; exists {
			t.Errorf("archive contains omitted node %q", omitted)
		}
	}
	var archivedMetadata Metadata
	if err := json.Unmarshal(entries["metadata.json"], &archivedMetadata); err != nil {
		t.Fatal(err)
	}
	if len(archivedMetadata.Omissions) != len(wantOmissions) {
		t.Fatalf("encrypted metadata omissions = %#v", archivedMetadata.Omissions)
	}

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(projectDir, "configs")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(projectDir, "secrets")); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(
		context.Background(),
		created.Name,
		testDecryptOptions,
	); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, targetPath, "current\n")
	for omitted := range wantOmissions {
		restored := filepath.Join(projectDir, filepath.FromSlash(omitted))
		if _, err := os.Lstat(restored); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("restore recreated omitted node %q: %v", omitted, err)
		}
	}
}

func TestCreateRejectsUnsafeSymlinkAndSpecialFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX filesystem nodes are unavailable")
	}
	tests := []struct {
		name  string
		setup func(t *testing.T, appRoot string)
	}{
		{
			name: "broken relative symlink",
			setup: func(t *testing.T, appRoot string) {
				t.Helper()
				if err := os.Symlink(
					"missing.log",
					filepath.Join(appRoot, "broken.log"),
				); err != nil {
					t.Skipf("symlink unsupported: %v", err)
				}
			},
		},
		{
			name: "relative symlink escaping managed root",
			setup: func(t *testing.T, appRoot string) {
				t.Helper()
				outside := filepath.Join(
					filepath.Dir(filepath.Dir(appRoot)),
					"outside.log",
				)
				if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(
					"../../outside.log",
					filepath.Join(appRoot, "outside-link.log"),
				); err != nil {
					t.Skipf("symlink unsupported: %v", err)
				}
			},
		},
		{
			name: "symlink to directory",
			setup: func(t *testing.T, appRoot string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(appRoot, "logs"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(
					"logs",
					filepath.Join(appRoot, "logs-link"),
				); err != nil {
					t.Skipf("symlink unsupported: %v", err)
				}
			},
		},
		{
			name: "fifo",
			setup: func(t *testing.T, appRoot string) {
				t.Helper()
				if err := syscall.Mkfifo(
					filepath.Join(appRoot, "events.fifo"),
					0o600,
				); err != nil {
					t.Skipf("FIFO unsupported: %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projectDir := seedBackupProject(t)
			test.setup(t, filepath.Join(projectDir, "configs", "app"))
			manager := NewManager(projectDir)
			if _, err := manager.Create(
				context.Background(),
				testEncryptOptions,
			); err == nil {
				t.Fatal("Create accepted an unsafe filesystem node")
			}
			entries, err := os.ReadDir(manager.backupDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("failed Create left backup artifacts: %#v", entries)
			}
		})
	}
}

func TestCreateRejectsManagedRootContainingBackupDirectory(t *testing.T) {
	projectDir := seedBackupProject(t)
	manager := NewManager(projectDir)
	_, err := manager.CreateWithRoots(
		context.Background(),
		testEncryptOptions,
		ManagedRoots{
			ConfigPath:  projectDir,
			SecretsPath: filepath.Join(projectDir, "secrets"),
		},
	)
	if err == nil || !strings.Contains(err.Error(), "backup directory") {
		t.Fatalf("CreateWithRoots error = %v, want backup self-ingestion rejection", err)
	}
	entries, readErr := os.ReadDir(manager.backupDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected self-ingestion left backup artifacts: %#v", entries)
	}
}

func TestCreateWithRootsDoesNotRereadMutableManagedPaths(t *testing.T) {
	projectDir := seedBackupProject(t)
	outsideConfig := filepath.Join(t.TempDir(), "outside-config")
	if err := os.MkdirAll(outsideConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(outsideConfig, "outside.yml"),
		[]byte("MUST_NOT_ENTER_BACKUP\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(projectDir, ".sdbx.yaml"),
		[]byte(
			"config_path: "+outsideConfig+"\n"+
				"secrets_path: ./secrets\n",
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	created, err := NewManager(projectDir).CreateWithRoots(
		context.Background(),
		testEncryptOptions,
		ManagedRoots{
			ConfigPath:  filepath.Join(projectDir, "configs"),
			SecretsPath: filepath.Join(projectDir, "secrets"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	body := decryptArchiveBody(t, created.Path)
	if !strings.Contains(body, "enabled: true") {
		t.Fatal("backup omitted state from the verified config root")
	}
	if strings.Contains(body, "MUST_NOT_ENTER_BACKUP") {
		t.Fatal("backup followed config_path reread after verification")
	}
}

func TestBackupBudgetRejectsExcessiveSources(t *testing.T) {
	budget := &backupBudget{
		nodes:     maxBackupNodes,
		entries:   1,
		total:     maxRestoreTotalBytes,
		pathBytes: int64(len("metadata.json")),
	}
	if err := budget.visitNode(); err == nil {
		t.Fatal("backup node budget accepted an extra filesystem entry")
	}
	budget.nodes = 0
	if err := budget.reserveFile("configs/extra", 1); err == nil {
		t.Fatal("backup byte budget accepted an oversized source set")
	}
}

type endlessZeroReader struct{}

func (endlessZeroReader) Read(data []byte) (int, error) {
	for index := range data {
		data[index] = 0
	}
	return len(data), nil
}

func TestDiscardRestoreEntryStreamsWithoutEntrySizedAllocation(t *testing.T) {
	const logicalSize = int64(128 << 20)
	allocations := testing.AllocsPerRun(3, func() {
		reader := io.LimitReader(endlessZeroReader{}, logicalSize)
		if err := discardExactRestoreEntry(
			context.Background(),
			reader,
			logicalSize,
		); err != nil {
			panic(err)
		}
	})
	if allocations > 20 {
		t.Fatalf("streaming discard used %.0f allocations, want at most 20", allocations)
	}
}

func TestRestoreUsesFixedConfiguredRoots(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	configRoot := filepath.Join(root, "external-config")
	secretsRoot := filepath.Join(root, "external-secrets")
	archiveConfigRoot := filepath.Join(root, "archive-controlled")
	archiveSecretsRoot := filepath.Join(root, "archive-secrets")
	if err := os.MkdirAll(projectDir, 0o700); err != nil {
		t.Fatal(err)
	}
	projectConfig := "config_path: " + configRoot + "\nsecrets_path: " + secretsRoot + "\n"
	if err := os.WriteFile(filepath.Join(projectDir, ".sdbx.yaml"), []byte(projectConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(projectDir)
	backupName := "external" + backupSuffix
	writeTestArchive(t, filepath.Join(prepareBackupDir(t, manager), backupName), []tarEntry{
		{name: "metadata.json", body: validMetadata(), mode: 0o600},
		{
			name: ".sdbx.yaml",
			body: []byte(
				"config_path: " + archiveConfigRoot + "\n" +
					"secrets_path: " + archiveSecretsRoot + "\n",
			),
			mode: 0o600,
		},
		{name: "configs/app/config.yml", body: []byte("ok"), mode: 0o600},
		{name: "secrets/token.txt", body: []byte("secret"), mode: 0o600},
	})
	if err := manager.Restore(context.Background(), backupName, testDecryptOptions); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, filepath.Join(configRoot, "app", "config.yml"), "ok")
	assertFileContent(t, filepath.Join(secretsRoot, "token.txt"), "secret")
	if _, err := os.Stat(filepath.Join(archiveConfigRoot, "app", "config.yml")); !os.IsNotExist(err) {
		t.Fatalf("archive-controlled config root was used, stat err=%v", err)
	}
}

func TestRestoreWithVerifiedRootsDoesNotRereadMutableManagedPaths(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	verifiedConfig := filepath.Join(root, "verified-config")
	verifiedSecrets := filepath.Join(root, "verified-secrets")
	racedConfig := filepath.Join(root, "raced-config")
	for _, directory := range []string{
		projectDir,
		verifiedConfig,
		verifiedSecrets,
		racedConfig,
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(projectDir, ".sdbx.yaml"),
		[]byte(
			"config_path: "+racedConfig+"\n"+
				"secrets_path: "+verifiedSecrets+"\n",
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(projectDir)
	backupName := "fixed-roots" + backupSuffix
	writeTestArchive(t, filepath.Join(prepareBackupDir(t, manager), backupName), []tarEntry{
		{name: "metadata.json", body: validMetadata(), mode: 0o600},
		{name: "configs/app/config.yml", body: []byte("verified-target"), mode: 0o600},
	})
	if err := manager.RestoreWithHooks(
		context.Background(),
		backupName,
		testDecryptOptions,
		RestoreHooks{
			VerifiedRoots: &ManagedRoots{
				ConfigPath:  verifiedConfig,
				SecretsPath: verifiedSecrets,
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	assertFileContent(
		t,
		filepath.Join(verifiedConfig, "app", "config.yml"),
		"verified-target",
	)
	if _, err := os.Stat(filepath.Join(racedConfig, "app", "config.yml")); !os.IsNotExist(err) {
		t.Fatalf("restore followed reread config root, stat err=%v", err)
	}
}

func TestRestoreRejectsManagedRootContainingProject(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "managed", "project")
	if err := os.MkdirAll(projectDir, 0o700); err != nil {
		t.Fatal(err)
	}
	err := validateRestoreTargetPaths(restoreTargets{
		projectPath: projectDir,
		configPath:  filepath.Join(root, "managed"),
		secretsPath: filepath.Join(projectDir, "secrets"),
	})
	if err == nil || !strings.Contains(err.Error(), "must not contain") {
		t.Fatalf("validateRestoreTargetPaths error = %v, want ancestor alias rejection", err)
	}
}

func TestBackupRestoreWithAbsolutePathMigratedDeployment(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	configRoot := filepath.Join(root, "configs")
	secretsRoot := filepath.Join(root, "secrets")
	if err := os.MkdirAll(filepath.Join(configRoot, "app"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secretsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(projectDir, 0o700); err != nil {
		t.Fatal(err)
	}
	projectConfig := "config_path: " + configRoot + "\nsecrets_path: " + secretsRoot + "\n"
	if err := os.WriteFile(filepath.Join(projectDir, ".sdbx.yaml"), []byte(projectConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configRoot, "app", "config.yml"), []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretsRoot, "token.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(projectDir)
	backup, err := manager.Create(context.Background(), testEncryptOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(configRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(secretsRoot); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), backup.Name, testDecryptOptions); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, filepath.Join(configRoot, "app", "config.yml"), "managed")
	assertFileContent(t, filepath.Join(secretsRoot, "token.txt"), "secret")
}

func TestPreserveProjectRestoreRelocatesCompatibleStateToTargetRoots(t *testing.T) {
	root := t.TempDir()
	sourceProject := filepath.Join(root, "source-project")
	sourceConfig := filepath.Join(root, "source-config")
	sourceSecrets := filepath.Join(root, "source-secrets")
	for _, directory := range []string{
		sourceProject,
		filepath.Join(sourceConfig, "app"),
		filepath.Join(sourceConfig, "traefik"),
		sourceSecrets,
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sourceIntent := "config_path: " + sourceConfig + "\nsecrets_path: " + sourceSecrets + "\n"
	for filePath, content := range map[string]string{
		filepath.Join(sourceProject, ".sdbx.yaml"):            sourceIntent,
		filepath.Join(sourceProject, ".sdbx.lock"):            "source-lock\n",
		filepath.Join(sourceProject, "compose.yaml"):          "source-compose\n",
		filepath.Join(sourceProject, ".env"):                  "SOURCE_ENV=1\n",
		filepath.Join(sourceConfig, "app", "config.yml"):      "source-user-state\n",
		filepath.Join(sourceConfig, "traefik", "traefik.yml"): "source-generated\n",
		filepath.Join(sourceSecrets, "token.txt"):             "source-secret\n",
	} {
		if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sourceManager := NewManager(sourceProject)
	created, err := sourceManager.Create(context.Background(), testEncryptOptions)
	if err != nil {
		t.Fatal(err)
	}

	targetProject := filepath.Join(root, "target-project")
	targetConfig := filepath.Join(root, "target-config")
	targetSecrets := filepath.Join(root, "target-secrets")
	for _, directory := range []string{
		filepath.Join(targetProject, "backups"),
		filepath.Join(targetConfig, "app"),
		filepath.Join(targetConfig, "traefik"),
		targetSecrets,
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	targetIntent := "config_path: " + targetConfig + "\nsecrets_path: " + targetSecrets + "\n"
	targetFiles := map[string]string{
		filepath.Join(targetProject, ".sdbx.yaml"):            targetIntent,
		filepath.Join(targetProject, ".sdbx.lock"):            "target-lock\n",
		filepath.Join(targetProject, "compose.yaml"):          "target-compose\n",
		filepath.Join(targetProject, ".env"):                  "TARGET_ENV=1\n",
		filepath.Join(targetConfig, "app", "config.yml"):      "target-user-state\n",
		filepath.Join(targetConfig, "traefik", "traefik.yml"): "target-generated\n",
		filepath.Join(targetSecrets, "token.txt"):             "target-secret\n",
	}
	for filePath, content := range targetFiles {
		if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive, err := os.ReadFile(created.Path)
	if err != nil {
		t.Fatal(err)
	}
	targetArchive := filepath.Join(targetProject, "backups", created.Name)
	if err := os.WriteFile(targetArchive, archive, 0o600); err != nil {
		t.Fatal(err)
	}

	inspected := make(map[string]bool)
	targetManager := NewManager(targetProject)
	if err := targetManager.RestoreWithHooks(
		context.Background(),
		created.Name,
		testDecryptOptions,
		RestoreHooks{
			PreserveProject: true,
			SkipConfigPaths: []string{"traefik/traefik.yml"},
			InspectProjectFile: func(name string, _ []byte) error {
				inspected[name] = true
				return nil
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{".sdbx.yaml", ".sdbx.lock"} {
		if !inspected[required] {
			t.Fatalf("portable restore did not inspect %s", required)
		}
	}
	for filePath, content := range map[string]string{
		filepath.Join(targetProject, ".sdbx.yaml"):            targetIntent,
		filepath.Join(targetProject, ".sdbx.lock"):            "target-lock\n",
		filepath.Join(targetProject, "compose.yaml"):          "target-compose\n",
		filepath.Join(targetProject, ".env"):                  "TARGET_ENV=1\n",
		filepath.Join(targetConfig, "traefik", "traefik.yml"): "target-generated\n",
		filepath.Join(targetConfig, "app", "config.yml"):      "source-user-state\n",
		filepath.Join(targetSecrets, "token.txt"):             "source-secret\n",
	} {
		assertFileContent(t, filePath, content)
	}
	assertNoRestoreArtifactsInRoots(t, targetProject, targetConfig, targetSecrets)
}

func TestDeleteRejectsTraversalAndSymlink(t *testing.T) {
	projectDir := t.TempDir()
	manager := NewManager(projectDir)
	backupDir := prepareBackupDir(t, manager)
	outside := filepath.Join(projectDir, "outside"+backupSuffix)
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../outside" + backupSuffix, "nested/backup" + backupSuffix, "plain.tar.gz"} {
		if err := manager.Delete(context.Background(), name); err == nil {
			t.Fatalf("Delete accepted %q", name)
		}
	}
	link := filepath.Join(backupDir, "link"+backupSuffix)
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := manager.Delete(context.Background(), filepath.Base(link)); err == nil {
		t.Fatal("Delete followed backup symlink")
	}
	assertFileContent(t, outside, "keep")
}

func TestListIgnoresPlaintextAndSymlinkArchives(t *testing.T) {
	projectDir := seedBackupProject(t)
	manager := NewManager(projectDir)
	backup, err := manager.Create(context.Background(), testEncryptOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.backupDir, "legacy.tar.gz"), []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup.Path, filepath.Join(manager.backupDir, "link"+backupSuffix)); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	backups, err := manager.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 || backups[0].Name != backup.Name {
		t.Fatalf("List = %#v, want only encrypted regular backup", backups)
	}
}

func TestRestoreBoundsAndHeaderPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		header tar.Header
	}{
		{
			name:   "oversized file",
			header: tar.Header{Name: "configs/huge.db", Typeflag: tar.TypeReg, Mode: 0o600, Size: maxRestoreFileBytes + 1},
		},
		{
			name:   "negative file",
			header: tar.Header{Name: "configs/negative.db", Typeflag: tar.TypeReg, Mode: 0o600, Size: -1},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateArchiveHeader(&test.header, false); err != nil {
				t.Fatalf("header path policy rejected before size policy: %v", err)
			}
			if err := validateRestoreSize(&test.header, 0); err == nil {
				t.Fatal("size policy accepted hostile header")
			}
		})
	}
	if err := validateRestoreEntryCount(maxRestoreEntries + 1); err == nil {
		t.Fatal("entry-count policy accepted an oversized archive")
	}
	totalHeader := &tar.Header{
		Name:     "configs/total.db",
		Typeflag: tar.TypeReg,
		Mode:     0o600,
		Size:     2,
	}
	if err := validateRestoreSize(totalHeader, maxRestoreTotalBytes-1); err == nil {
		t.Fatal("total-size policy accepted an oversized archive")
	}
}

func TestRestoreJournalWriterEnforcesReaderSizeLimit(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "journal")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writer := &restoreJournalWriter{
		file: file,
		size: maxRestoreJournalSize - 1,
	}
	if err := writer.append(restoreJournalRecord{Event: restoreEventCommit}); err == nil {
		t.Fatal("journal writer exceeded the recovery reader limit")
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("rejected journal record wrote %d bytes", info.Size())
	}
}

func TestRootRecoveryRejectsJournalOwnedByAnotherIdentity(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires a Linux root test environment")
	}
	projectDir := t.TempDir()
	journalPath := filepath.Join(projectDir, restoreJournalName)
	if err := os.WriteFile(journalPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(journalPath, 12345, 12346); err != nil {
		t.Fatal(err)
	}
	projectRoot, err := os.OpenRoot(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	defer projectRoot.Close()
	_, _, err = loadRestoreJournal(projectRoot, projectDir)
	if err == nil || !strings.Contains(err.Error(), "owned") {
		t.Fatalf("loadRestoreJournal error = %v, want owner rejection", err)
	}
}

func TestValidateArchiveRejectsOversizedTrailingGzipMember(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "trailing"+backupSuffix)
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := age.NewScryptRecipient(string(testEncryptOptions.Passphrase))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := age.Encrypt(file, recipient)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(encrypted)
	archive := tar.NewWriter(compressed)
	metadata := validMetadata()
	if err := archive.WriteHeader(&tar.Header{
		Name:     "metadata.json",
		Mode:     0o600,
		Size:     int64(len(metadata)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(metadata); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	trailing := gzip.NewWriter(encrypted)
	if _, err := trailing.Write(bytes.Repeat([]byte{'x'}, int(maxRestoreTrailing+1))); err != nil {
		t.Fatal(err)
	}
	if err := trailing.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	archiveFile, err := os.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer archiveFile.Close()
	identities, err := decryptionIdentities(testDecryptOptions)
	if err != nil {
		t.Fatal(err)
	}
	err = validateArchive(context.Background(), archiveFile, identities)
	if err == nil || !strings.Contains(err.Error(), "trailing bytes") {
		t.Fatalf("validateArchive error = %v, want bounded trailing-data rejection", err)
	}
}

type tarEntry struct {
	name     string
	body     []byte
	mode     int64
	entry    byte
	linkName string
}

func writeTestArchive(t *testing.T, destination string, entries []tarEntry) {
	t.Helper()
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := age.NewScryptRecipient(string(testEncryptOptions.Passphrase))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := age.Encrypt(file, recipient)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(encrypted)
	archive := tar.NewWriter(compressed)
	for _, entry := range entries {
		entryType := entry.entry
		if entryType == 0 {
			entryType = tar.TypeReg
		}
		size := int64(len(entry.body))
		if entryType != tar.TypeReg && entryType != tar.TypeRegA {
			size = 0
		}
		header := &tar.Header{
			Name:     entry.name,
			Mode:     entry.mode,
			Size:     size,
			Typeflag: entryType,
			Linkname: entry.linkName,
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := archive.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func seedBackupProject(t *testing.T) string {
	t.Helper()
	projectDir := t.TempDir()
	return seedBackupProjectAt(t, projectDir)
}

func seedBackupProjectAt(t *testing.T, projectDir string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(projectDir, "configs", "app"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(projectDir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(projectDir, ".sdbx.yaml"),
		[]byte("config_path: ./configs\nsecrets_path: ./secrets\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "compose.yaml"), []byte("name: sdbx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(projectDir, "configs", "app", "config.yml"),
		[]byte("enabled: true\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(projectDir, "secrets", "token.txt"),
		[]byte("TOP_SECRET_CANARY\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return projectDir
}

func validMetadata() []byte {
	return []byte(`{"version":"2.0.0","timestamp":"2026-07-28T00:00:00Z"}`)
}

func prepareBackupDir(t *testing.T, manager *Manager) string {
	t.Helper()
	if err := os.MkdirAll(manager.backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return manager.backupDir
}

func assertFileContent(t *testing.T, filePath, expected string) {
	t.Helper()
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", filePath, err)
	}
	if string(data) != expected {
		t.Fatalf("%s = %q, want %q", filePath, data, expected)
	}
}

func assertFileOwnership(t *testing.T, filePath string, uid, gid int) {
	t.Helper()
	info, err := os.Lstat(filePath)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s has no syscall.Stat_t", filePath)
	}
	if int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Fatalf(
			"%s ownership = %d:%d, want %d:%d",
			filePath,
			stat.Uid,
			stat.Gid,
			uid,
			gid,
		)
	}
}

func assertNoRestoreTransactionArtifacts(t *testing.T, projectDir string) {
	t.Helper()
	assertNoRestoreArtifactsInRoots(
		t,
		projectDir,
		filepath.Join(projectDir, "configs"),
		filepath.Join(projectDir, "secrets"),
	)
}

func assertNoRestoreArtifactsInRoots(t *testing.T, roots ...string) {
	t.Helper()
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Name() == restoreJournalName ||
				strings.HasPrefix(entry.Name(), restoreTransactionTag) {
				t.Fatalf("restore transaction artifact remains at %s", filepath.Join(root, entry.Name()))
			}
		}
	}
}

func decryptArchiveBody(t *testing.T, archivePath string) string {
	t.Helper()
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	identity, err := age.NewScryptIdentity(string(testDecryptOptions.Passphrase))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := age.Decrypt(file, identity)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := gzip.NewReader(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	var body strings.Builder
	for {
		_, err := archive.Next()
		if err == io.EOF {
			return body.String()
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		body.Write(data)
	}
}

func decryptArchiveEntries(t *testing.T, archivePath string) map[string][]byte {
	t.Helper()
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	identity, err := age.NewScryptIdentity(string(testDecryptOptions.Passphrase))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := age.Decrypt(file, identity)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := gzip.NewReader(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	entries := make(map[string][]byte)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return entries
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = body
	}
}
