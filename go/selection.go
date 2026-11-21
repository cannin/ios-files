package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// A backupCandidate associates a valid backup directory with its timestamp.
type backupCandidate struct {
	directory string
	date      time.Time
}

// resolveBackupDirectory returns the selected device backup directory. inputPath
// may identify a device backup directly or a parent directory, in which case the
// newest valid child backup is returned.
func resolveBackupDirectory(inputPath string) (string, error) {
	expandedPath, err := expandHomeDirectory(inputPath)
	if err != nil {
		return "", fmt.Errorf("expand backup path: %w", err)
	}
	absolutePath, err := filepath.Abs(expandedPath)
	if err != nil {
		return "", fmt.Errorf("resolve backup path: %w", err)
	}
	info, err := os.Stat(absolutePath)
	if err != nil {
		return "", fmt.Errorf("inspect backup path %q: %w", absolutePath, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("backup path is not a directory: %s", absolutePath)
	}
	if isDeviceBackupDirectory(absolutePath) {
		return absolutePath, nil
	}

	entries, err := os.ReadDir(absolutePath)
	if err != nil {
		return "", fmt.Errorf("read backup root: %w", err)
	}
	candidates := make([]backupCandidate, 0, len(entries))
	for _, entry := range entries {
		candidatePath := filepath.Join(absolutePath, entry.Name())
		candidateInfo, err := os.Stat(candidatePath)
		if err != nil || !candidateInfo.IsDir() || !isDeviceBackupDirectory(candidatePath) {
			continue
		}
		manifestData, err := readManifest(filepath.Join(candidatePath, "Manifest.plist"))
		if err != nil {
			continue
		}
		candidateDate := manifestData.Date
		if candidateDate.IsZero() {
			candidateDate = candidateInfo.ModTime()
		}
		candidates = append(candidates, backupCandidate{
			directory: candidatePath,
			date:      candidateDate,
		})
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf(
			"no valid device backups found in %s; expected child directories containing Manifest.plist and Manifest.db",
			absolutePath,
		)
	}

	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].date.Equal(candidates[right].date) {
			return candidates[left].directory > candidates[right].directory
		}
		return candidates[left].date.After(candidates[right].date)
	})
	return candidates[0].directory, nil
}

// expandHomeDirectory returns inputPath with a leading home-directory shorthand
// expanded. Named-user home paths are not supported.
func expandHomeDirectory(inputPath string) (string, error) {
	if inputPath == "~" || strings.HasPrefix(inputPath, "~/") || strings.HasPrefix(inputPath, `~\`) {
		homeDirectory, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if inputPath == "~" {
			return homeDirectory, nil
		}
		relativePath := strings.TrimLeft(inputPath[1:], `/\`)
		return filepath.Join(homeDirectory, filepath.FromSlash(relativePath)), nil
	}
	if strings.HasPrefix(inputPath, "~") {
		return "", errors.New("named-user home paths are not supported")
	}
	return inputPath, nil
}

// isDeviceBackupDirectory reports whether directory contains the manifest files
// required to open a device backup.
func isDeviceBackupDirectory(directory string) bool {
	return isRegularFile(filepath.Join(directory, "Manifest.plist")) &&
		isRegularFile(filepath.Join(directory, "Manifest.db"))
}

// isRegularFile reports whether filename identifies a regular file. Symbolic
// links are followed.
func isRegularFile(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && info.Mode().IsRegular()
}
