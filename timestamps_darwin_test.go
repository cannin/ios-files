//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestApplyFileTimestampsSetsCreationTimeOnDarwin(t *testing.T) {
	t.Parallel()

	filename := filepath.Join(t.TempDir(), "timestamp-test")
	if err := os.WriteFile(filename, []byte("test"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	createdAt := time.Date(2020, time.January, 2, 3, 4, 5, 0, time.UTC)
	modifiedAt := time.Date(2021, time.March, 4, 5, 6, 7, 0, time.UTC)
	if err := applyFileTimestamps(filename, createdAt, modifiedAt); err != nil {
		t.Fatalf("applyFileTimestamps() error = %v", err)
	}

	var stat unix.Stat_t
	if err := unix.Stat(filename, &stat); err != nil {
		t.Fatalf("unix.Stat() error = %v", err)
	}
	actualCreatedAt := time.Unix(stat.Btim.Sec, stat.Btim.Nsec)
	if !actualCreatedAt.Equal(createdAt) {
		t.Fatalf("creation time = %v, want %v", actualCreatedAt, createdAt)
	}
}
