package main

import (
	"bytes"
	"testing"
	"time"

	"howett.net/plist"
)

func TestParseFileMetadata(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.July, 21, 11, 15, 0, 0, time.UTC)
	modifiedAt := time.Date(2026, time.July, 22, 12, 30, 0, 0, time.UTC)
	wantKey := bytes.Repeat([]byte{0xab}, 40)
	encodedKey := append([]byte{0, 0, 0, 1}, wantKey...)
	archive := map[string]any{
		"$top": map[string]any{"root": plist.UID(1)},
		"$objects": []any{
			"$null",
			map[string]any{
				"Size":            uint64(12345),
				"ProtectionClass": uint64(3),
				"EncryptionKey":   plist.UID(2),
				"Birth":           createdAt,
				"LastModified":    modifiedAt,
			},
			map[string]any{"NS.data": encodedKey},
		},
	}
	data, err := plist.Marshal(archive, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("plist.Marshal() error = %v", err)
	}

	metadata, err := parseFileMetadata(data, true)
	if err != nil {
		t.Fatalf("parseFileMetadata() error = %v", err)
	}
	if metadata.size != 12345 || metadata.protectionClass != 3 {
		t.Fatalf("parseFileMetadata() returned unexpected values: %+v", metadata)
	}
	if !bytes.Equal(metadata.encryptionKey, wantKey) {
		t.Fatalf("parseFileMetadata() encryption key = %X, want %X", metadata.encryptionKey, wantKey)
	}
	if !metadata.createdAt.Equal(createdAt) {
		t.Fatalf("parseFileMetadata() creation time = %v, want %v", metadata.createdAt, createdAt)
	}
	if !metadata.modifiedAt.Equal(modifiedAt) {
		t.Fatalf("parseFileMetadata() modified time = %v, want %v", metadata.modifiedAt, modifiedAt)
	}
}
