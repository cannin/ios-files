package main

import (
	"encoding/json"
	"os"
)

// An extractionDebugLog writes newline-delimited JSON events to a local file.
type extractionDebugLog struct {
	file    *os.File
	encoder *json.Encoder
}

// newExtractionDebugLog creates a diagnostic log in the current directory.
func newExtractionDebugLog() (*extractionDebugLog, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(workingDirectory, "ios-files-debug-*.jsonl")
	if err != nil {
		return nil, err
	}
	return &extractionDebugLog{file: file, encoder: json.NewEncoder(file)}, nil
}

// Filename returns the diagnostic log's local path.
func (log *extractionDebugLog) Filename() string {
	return log.file.Name()
}

// Record appends event to the diagnostic log.
func (log *extractionDebugLog) Record(event ExtractionDebugEvent) {
	_ = log.encoder.Encode(event)
}

// Close closes the diagnostic log.
func (log *extractionDebugLog) Close() error {
	return log.file.Close()
}
