//go:build !darwin

package main

import "time"

// setFileCreationTime is a no-op on platforms without the macOS birth-time API.
func setFileCreationTime(_ string, _ time.Time) error {
	return nil
}
