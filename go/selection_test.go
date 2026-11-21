package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"howett.net/plist"
)

func TestResolveBackupDirectoryAcceptsDirectBackup(t *testing.T) {
	t.Parallel()

	directory := createBackupCandidate(t, t.TempDir(), "device", time.Time{})
	want, err := filepath.Abs(directory)
	if err != nil {
		t.Fatalf("filepath.Abs() error = %v", err)
	}
	for _, inputPath := range []string{directory, directory + string(filepath.Separator)} {
		got, err := resolveBackupDirectory(inputPath)
		if err != nil {
			t.Fatalf("resolveBackupDirectory(%q) error = %v", inputPath, err)
		}
		if got != want {
			t.Fatalf("resolveBackupDirectory(%q) = %q, want %q", inputPath, got, want)
		}
	}
}

func TestResolveBackupDirectorySelectsLatestManifestDate(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	createBackupCandidate(t, root, "older", time.Date(2026, time.July, 1, 12, 0, 0, 0, time.UTC))
	latest := createBackupCandidate(t, root, "newer", time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC))

	for _, inputPath := range []string{root, root + string(filepath.Separator)} {
		got, err := resolveBackupDirectory(inputPath)
		if err != nil {
			t.Fatalf("resolveBackupDirectory(%q) error = %v", inputPath, err)
		}
		if got != latest {
			t.Fatalf("resolveBackupDirectory(%q) = %q, want %q", inputPath, got, latest)
		}
	}
}

func createBackupCandidate(t *testing.T, root, name string, date time.Time) string {
	t.Helper()
	directory := filepath.Join(root, name)
	writeTestManifest(t, directory, manifest{Date: date})
	if err := os.WriteFile(filepath.Join(directory, "Manifest.db"), []byte("test"), 0o600); err != nil {
		t.Fatalf("write Manifest.db: %v", err)
	}
	return directory
}

// writeTestManifest creates a backup directory and writes its Manifest.plist.
func writeTestManifest(t *testing.T, directory string, value manifest) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatalf("os.MkdirAll() error = %v", err)
	}
	manifestData, err := plist.Marshal(value, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("plist.Marshal() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "Manifest.plist"), manifestData, 0o600); err != nil {
		t.Fatalf("write Manifest.plist: %v", err)
	}
}
