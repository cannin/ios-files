package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractionDebugLogWritesJSONLines(t *testing.T) {
	t.Parallel()

	log, err := newExtractionDebugLog()
	if err != nil {
		t.Fatalf("newExtractionDebugLog() error = %v", err)
	}
	filename := log.Filename()
	t.Cleanup(func() {
		os.Remove(filename)
	})
	log.Record(ExtractionDebugEvent{
		Phase:          "start",
		Index:          1,
		Total:          10,
		RelativePath:   "Media/DCIM/100APPLE/IMG_0001.JPG",
		OutputFilename: "IMG_0001.JPG",
	})
	if err := log.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}
	if filepath.Dir(filename) != workingDirectory {
		t.Fatalf("debug log directory = %q, want %q", filepath.Dir(filename), workingDirectory)
	}

	file, err := os.Open(filename)
	if err != nil {
		t.Fatalf("os.Open() error = %v", err)
	}
	defer file.Close()
	var event ExtractionDebugEvent
	if err := json.NewDecoder(bufio.NewReader(file)).Decode(&event); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if event.Phase != "start" || event.Index != 1 || event.OutputFilename != "IMG_0001.JPG" {
		t.Fatalf("decoded debug event = %+v", event)
	}
}
