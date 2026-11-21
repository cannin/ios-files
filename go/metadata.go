package main

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"howett.net/plist"
)

// A fileMetadata contains the values needed to restore a backup file.
type fileMetadata struct {
	size            int64
	protectionClass uint32
	encryptionKey   []byte
	createdAt       time.Time
	modifiedAt      time.Time
}

// parseFileMetadata returns file metadata decoded from an NSKeyedArchiver record
// stored in Manifest.db. Encrypted files also require a class and a wrapped key.
func parseFileMetadata(data []byte, encrypted bool) (fileMetadata, error) {
	var archive map[string]any
	decoder := plist.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&archive); err != nil {
		return fileMetadata{}, fmt.Errorf("decode file metadata plist: %w", err)
	}

	objects, ok := archive["$objects"].([]any)
	if !ok {
		return fileMetadata{}, errors.New("file metadata has no $objects array")
	}
	top, ok := archive["$top"].(map[string]any)
	if !ok {
		return fileMetadata{}, errors.New("file metadata has no $top dictionary")
	}
	rootIndex, err := uidIndex(top["root"], len(objects))
	if err != nil {
		return fileMetadata{}, fmt.Errorf("resolve metadata root: %w", err)
	}
	root, ok := objects[rootIndex].(map[string]any)
	if !ok {
		return fileMetadata{}, errors.New("file metadata root is not a dictionary")
	}

	size, err := integerValue(root["Size"])
	if err != nil || size < 0 {
		return fileMetadata{}, errors.New("file metadata contains an invalid Size")
	}
	metadata := fileMetadata{size: size}
	if createdAt, ok := root["Birth"].(time.Time); ok {
		metadata.createdAt = createdAt
	}
	if modifiedAt, ok := root["LastModified"].(time.Time); ok {
		metadata.modifiedAt = modifiedAt
	}
	if !encrypted {
		return metadata, nil
	}

	protectionClass, err := integerValue(root["ProtectionClass"])
	if err != nil || protectionClass < 0 || protectionClass > int64(^uint32(0)) {
		return fileMetadata{}, errors.New("file metadata contains an invalid ProtectionClass")
	}

	encryptionReference, exists := root["EncryptionKey"]
	if !exists {
		return fileMetadata{}, errors.New("file metadata has no EncryptionKey")
	}
	encryptionIndex, err := uidIndex(encryptionReference, len(objects))
	if err != nil {
		return fileMetadata{}, fmt.Errorf("resolve encryption key: %w", err)
	}
	encryptionObject, ok := objects[encryptionIndex].(map[string]any)
	if !ok {
		return fileMetadata{}, errors.New("encryption key object is not a dictionary")
	}
	encodedKey, ok := encryptionObject["NS.data"].([]byte)
	if !ok || len(encodedKey) < 5 {
		return fileMetadata{}, errors.New("encryption key data is missing or truncated")
	}

	metadata.protectionClass = uint32(protectionClass)
	metadata.encryptionKey = append([]byte(nil), encodedKey[4:]...)
	return metadata, nil
}

// uidIndex returns the object-table index represented by a plist UID. It returns
// an error when value is not a UID or lies outside the object table.
func uidIndex(value any, objectCount int) (int, error) {
	uid, ok := value.(plist.UID)
	if !ok {
		return 0, fmt.Errorf("expected plist UID, got %T", value)
	}
	index := int(uid)
	if index < 0 || index >= objectCount {
		return 0, fmt.Errorf("UID %d is outside object table", index)
	}
	return index, nil
}

// integerValue returns value as an int64 when value is one of the integer types
// produced by property-list decoding and fits in the result type.
func integerValue(value any) (int64, error) {
	switch number := value.(type) {
	case int:
		return int64(number), nil
	case int8:
		return int64(number), nil
	case int16:
		return int64(number), nil
	case int32:
		return int64(number), nil
	case int64:
		return number, nil
	case uint:
		if uint64(number) > uint64(^uint64(0)>>1) {
			return 0, errors.New("integer is too large")
		}
		return int64(number), nil
	case uint8:
		return int64(number), nil
	case uint16:
		return int64(number), nil
	case uint32:
		return int64(number), nil
	case uint64:
		if number > uint64(^uint64(0)>>1) {
			return 0, errors.New("integer is too large")
		}
		return int64(number), nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", value)
	}
}
