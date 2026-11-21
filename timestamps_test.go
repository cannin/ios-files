package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyFileTimestampsSetsModificationTime(t *testing.T) {
	t.Parallel()

	filename := filepath.Join(t.TempDir(), "timestamp-test")
	if err := os.WriteFile(filename, []byte("test"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	modifiedAt := time.Date(2021, time.March, 4, 5, 6, 7, 0, time.UTC)
	if err := applyFileTimestamps(filename, time.Time{}, modifiedAt); err != nil {
		t.Fatalf("applyFileTimestamps() error = %v", err)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}
	if !info.ModTime().Equal(modifiedAt) {
		t.Fatalf("modification time = %v, want %v", info.ModTime(), modifiedAt)
	}
}
