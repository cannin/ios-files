package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func TestRunDisplaysHelp(t *testing.T) {
	t.Parallel()

	expectedText := []string{
		"Usage: ios-files [options]",
		"encrypted backup password file, or - for stdin (default: secure interactive prompt)",
		"Examples:",
		"ios-files --output-dir exported-files",
		"ios-files --backup /path/to/backup --output-dir /path/to/export",
		"ios-files -b /path/to/backup -p /path/to/password.txt --camera-roll=false",
	}
	for _, args := range [][]string{nil, {"-h"}} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		err := run(args, bytes.NewBuffer(nil), &stdout, &stderr)
		if err != nil {
			t.Fatalf("run(%v) error = %v", args, err)
		}
		for _, expected := range expectedText {
			if !strings.Contains(stderr.String(), expected) {
				t.Fatalf("run(%v) help output lacks %q: %q", args, expected, stderr.String())
			}
		}
	}
}

func TestRunExtractsUnencryptedBackupWithoutPassword(t *testing.T) {
	t.Parallel()

	backupDirectory := filepath.Join(t.TempDir(), "device #100%")
	writeTestManifest(t, backupDirectory, manifest{})
	manifestDatabase := openTestManifestDatabase(t, filepath.Join(backupDirectory, "Manifest.db"))
	outputDirectory := t.TempDir()
	plaintext := []byte("synthetic backup contents")
	modifiedAt := time.Date(2026, time.July, 22, 12, 30, 0, 0, time.UTC)
	metadata, err := plist.Marshal(map[string]any{
		"$top": map[string]any{"root": plist.UID(1)},
		"$objects": []any{"$null", map[string]any{
			"Size":         len(plaintext),
			"LastModified": modifiedAt,
		}},
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("marshal file metadata: %v", err)
	}
	cameraFilename := "IMG_0001.JPG"
	for _, fixture := range []struct {
		fileID, domain, relativePath string
	}{
		{strings.Repeat("a", 40), cameraRollDomainPattern, "Media/DCIM/100APPLE/" + cameraFilename},
		{strings.Repeat("b", 40), "HomeDomain", callHistoryRelativePath},
	} {
		inputDirectory := filepath.Join(backupDirectory, fixture.fileID[:2])
		if err := os.Mkdir(inputDirectory, 0o700); err != nil {
			t.Fatalf("create backup file directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(inputDirectory, fixture.fileID), plaintext, 0o600); err != nil {
			t.Fatalf("write backup file: %v", err)
		}
		if _, err := manifestDatabase.Exec(`INSERT INTO Files VALUES (?, ?, ?, ?, 1)`,
			fixture.fileID, fixture.domain, fixture.relativePath, metadata); err != nil {
			t.Fatalf("insert manifest row: %v", err)
		}
	}
	if err := manifestDatabase.Close(); err != nil {
		t.Fatalf("close fixture database: %v", err)
	}

	args := []string{"--backup", backupDirectory, "--output-dir", outputDirectory, "--call-history", "--debug=false"}
	var stdout, stderr bytes.Buffer
	if err := run(args, bytes.NewReader(nil), &stdout, &stderr); err != nil {
		t.Fatalf("run without password input: %v", err)
	}
	cameraOutput := filepath.Join(outputDirectory, "camera_roll", cameraFilename)
	assertFileContents(t, cameraOutput, plaintext)
	assertFileContents(t, filepath.Join(outputDirectory, "call_history.sqlite"), plaintext)
	info, err := os.Stat(cameraOutput)
	if err != nil {
		t.Fatalf("stat extracted camera file: %v", err)
	}
	if !info.ModTime().Equal(modifiedAt) {
		t.Fatalf("output modification time = %v, want %v", info.ModTime(), modifiedAt)
	}

	if err := os.WriteFile(cameraOutput, []byte("partial"), 0o600); err != nil {
		t.Fatalf("truncate exported camera file: %v", err)
	}
	stdout.Reset()
	args = append(args, "--password-file", filepath.Join(t.TempDir(), "missing"))
	if err := run(args, bytes.NewReader(nil), &stdout, &stderr); err != nil {
		t.Fatalf("run with unused password file: %v", err)
	}
	assertFileContents(t, cameraOutput, plaintext)
	if !strings.Contains(stdout.String(), "1 repaired size mismatches") {
		t.Fatalf("repair summary missing from stdout: %s", &stdout)
	}
	if strings.Contains(stderr.String(), "Backup password:") {
		t.Fatalf("unexpected password prompt: %s", &stderr)
	}
}

func TestRunReadsPasswordForEncryptedBackup(t *testing.T) {
	t.Parallel()

	backupDirectory := t.TempDir()
	writeTestManifest(t, backupDirectory, manifest{IsEncrypted: true})
	if err := os.WriteFile(filepath.Join(backupDirectory, "Manifest.db"), nil, 0o600); err != nil {
		t.Fatalf("write fixture database: %v", err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{"--backup", backupDirectory}, bytes.NewReader(nil), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "read backup password: password input is empty") {
		t.Fatalf("run with encrypted backup and empty stdin = %v, want password input error", err)
	}
}

func TestParseFlags(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	cfg, err := parseFlags([]string{"--backup", "backup", "-o", "results", "--call-history=true", "-r=false", "--debug=false"}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if cfg.backupPath != "backup" || cfg.outputPath != "results" {
		t.Fatalf("parseFlags() returned unexpected paths: %+v", cfg)
	}
	if !cfg.extractCallHistory || cfg.extractCameraRoll {
		t.Fatalf("parseFlags() returned unexpected extraction targets: %+v", cfg)
	}
	if cfg.debug {
		t.Fatalf("parseFlags() debug = true, want false")
	}
}

func TestParseFlagsDisablesCallHistoryByDefault(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	cfg, err := parseFlags([]string{"--backup", "backup"}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if cfg.extractCallHistory {
		t.Fatal("parseFlags() extractCallHistory = true, want false")
	}
}

func TestParseFlagsEnablesDebugByDefault(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	cfg, err := parseFlags([]string{"--backup", "backup"}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if !cfg.debug {
		t.Fatal("parseFlags() debug = false, want true")
	}
}

func TestParseFlagsOutputDirectory(t *testing.T) {
	t.Parallel()

	want := filepath.Join("tmp", "exported-files")
	for _, outputPath := range []string{want, want + string(filepath.Separator)} {
		var stderr bytes.Buffer
		cfg, err := parseFlags([]string{"--backup", "backup", "--output-dir", outputPath}, &stderr)
		if err != nil {
			t.Fatalf("parseFlags(%q) error = %v", outputPath, err)
		}
		if cfg.outputPath != want {
			t.Fatalf("parseFlags(%q) outputPath = %q, want %q", outputPath, cfg.outputPath, want)
		}
	}
}

func TestParseFlagsDefaultOutputDirectory(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	cfg, err := parseFlags([]string{"--backup", "backup"}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if cfg.outputPath != defaultOutputDirectory {
		t.Fatalf("parseFlags() outputPath = %q, want %q", cfg.outputPath, defaultOutputDirectory)
	}
}

func TestParseFlagsDefaultBackupDirectory(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	cfg, err := parseFlags(nil, &stderr)
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if cfg.backupPath != defaultBackupDirectory {
		t.Fatalf("parseFlags() backupPath = %q, want %q", cfg.backupPath, defaultBackupDirectory)
	}
}

func TestReadPasswordLine(t *testing.T) {
	t.Parallel()

	got, err := readPasswordLine(bytes.NewBufferString("secret\r\nignored\n"))
	if err != nil {
		t.Fatalf("readPasswordLine() error = %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("readPasswordLine() = %q, want %q", got, "secret")
	}
}
