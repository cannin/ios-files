package main

import (
	"fmt"
	"os"
	"time"
)

// applyFileTimestamps restores the original creation and modification times
// recorded in the iOS backup when those values are available.
func applyFileTimestamps(filename string, createdAt, modifiedAt time.Time) error {
	if !createdAt.IsZero() {
		if err := setFileCreationTime(filename, createdAt); err != nil {
			return fmt.Errorf("set output creation time: %w", err)
		}
	}
	if !modifiedAt.IsZero() {
		if err := os.Chtimes(filename, modifiedAt, modifiedAt); err != nil {
			return fmt.Errorf("set output modification time: %w", err)
		}
	}
	return nil
}
