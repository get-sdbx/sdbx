package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sdbx/sdbx/internal/config"
	"github.com/spf13/cobra"
)

func TestReadPrivatePassphraseFileRequiresPrivateRegularFile(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "passphrase.txt")
	if err := os.WriteFile(filePath, []byte("correct horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passphrase, err := readPrivatePassphraseFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(passphrase) != "correct horse" {
		t.Fatalf("passphrase = %q, want one trimmed line", passphrase)
	}
	zeroBytes(passphrase)

	if err := os.Chmod(filePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivatePassphraseFile(filePath); err == nil {
		t.Fatal("world-readable passphrase file was accepted")
	}

	if err := os.Remove(filePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filePath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := readPrivatePassphraseFile(filePath); err == nil {
		t.Fatal("symlinked passphrase file was accepted")
	}
}

func TestReadPrivatePassphraseFileRejectsMultipleLines(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "passphrase.txt")
	if err := os.WriteFile(filePath, []byte("first\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivatePassphraseFile(filePath); err == nil ||
		!strings.Contains(err.Error(), "exactly one line") {
		t.Fatalf("error = %v, want one-line rejection", err)
	}
}

func TestBackupOptionFlagsAreMutuallyExclusive(t *testing.T) {
	originalRecipient := backupRecipient
	originalPassphraseFile := backupPassphraseFile
	originalIdentityFile := backupIdentityFile
	originalRestorePassphraseFile := restorePassphraseFile
	t.Cleanup(func() {
		backupRecipient = originalRecipient
		backupPassphraseFile = originalPassphraseFile
		backupIdentityFile = originalIdentityFile
		restorePassphraseFile = originalRestorePassphraseFile
	})

	backupRecipient = "age1placeholder"
	backupPassphraseFile = "/private/passphrase"
	if _, err := backupCreateOptions(); err == nil {
		t.Fatal("backup create accepted recipient plus passphrase file")
	}

	backupIdentityFile = "/private/identity"
	restorePassphraseFile = "/private/passphrase"
	if _, err := backupRestoreOptions(); err == nil {
		t.Fatal("backup restore accepted identity plus passphrase file")
	}
}

func TestBackupDestructiveCommandsRequireExactConfirmation(t *testing.T) {
	originalRestore := backupRestoreConfirm
	originalDelete := backupDeleteConfirm
	t.Cleanup(func() {
		backupRestoreConfirm = originalRestore
		backupDeleteConfirm = originalDelete
	})

	for _, value := range []string{"", "yes", "RESTORE"} {
		backupRestoreConfirm = value
		err := runBackupRestore(backupRestoreCmd, []string{"backup.tar.gz.age"})
		if err == nil || !strings.Contains(err.Error(), "--confirm restore") {
			t.Fatalf("restore confirmation %q error = %v", value, err)
		}
	}
	for _, value := range []string{"", "yes", "DELETE"} {
		backupDeleteConfirm = value
		err := runBackupDelete(backupDeleteCmd, []string{"backup.tar.gz.age"})
		if err == nil || !strings.Contains(err.Error(), "--confirm delete") {
			t.Fatalf("delete confirmation %q error = %v", value, err)
		}
	}
}

func TestBackupCreateRequiresVerifiedGeneratedState(t *testing.T) {
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	projectDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domain = "backup-verification.example.test"
	if err := cfg.Save(filepath.Join(projectDir, ".sdbx.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(projectDir); err != nil {
		t.Fatal(err)
	}

	err = runBackupCreate(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(
		err.Error(),
		"backup source verification failed",
	) {
		t.Fatalf("unverified backup source error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(projectDir, "backups")); !os.IsNotExist(statErr) {
		t.Fatalf("unverified backup created output: %v", statErr)
	}
}
