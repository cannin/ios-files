package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func TestDecryptCBCFileUsesMetadataSize(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("camera data with a non-block length")
	padded := append([]byte(nil), plaintext...)
	paddingLength := aes.BlockSize - len(padded)%aes.BlockSize
	padded = append(padded, bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)...)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(encrypted, padded)

	inputPath := filepath.Join(t.TempDir(), "encrypted")
	if err := os.WriteFile(inputPath, encrypted, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var output bytes.Buffer
	expectedSize := int64(len(plaintext))
	if err := decryptCBCFile(inputPath, &output, key, &expectedSize); err != nil {
		t.Fatalf("decryptCBCFile() error = %v", err)
	}
	if !bytes.Equal(output.Bytes(), plaintext) {
		t.Fatalf("decryptCBCFile() = %q, want %q", output.Bytes(), plaintext)
	}
}

func TestExtractRecordVerifiesExistingFileWithoutOverwrite(t *testing.T) {
	t.Parallel()

	original := []byte("already extracted camera data")
	outputPath := filepath.Join(t.TempDir(), "IMG_0001.JPG")
	if err := os.WriteFile(outputPath, original, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	record := fileRecord{
		fileID:   strings.Repeat("a", 40),
		metadata: makeTestFileMetadata(t, int64(len(original))),
	}

	status, err := (&Backup{}).extractRecord(record, outputPath)
	if err != nil {
		t.Fatalf("extractRecord() error = %v", err)
	}
	if status != extractionStatusVerified {
		t.Fatalf("extractRecord() status = %v, want %v", status, extractionStatusVerified)
	}
	assertFileContents(t, outputPath, original)
}

func TestExtractRecordRepairsSizeMismatch(t *testing.T) {
	t.Parallel()

	keyEncryptionKey, wrappedFileKey, fileKey := testEncryptionKeys(t)
	plaintext := []byte("complete replacement camera data")
	fileID := strings.Repeat("b", 40)
	backupDirectory := t.TempDir()
	encryptedDirectory := filepath.Join(backupDirectory, fileID[:2])
	if err := os.Mkdir(encryptedDirectory, 0o700); err != nil {
		t.Fatalf("os.Mkdir() error = %v", err)
	}
	writeEncryptedTestFile(t, filepath.Join(encryptedDirectory, fileID), plaintext, fileKey)

	outputPath := filepath.Join(t.TempDir(), "IMG_0002.JPG")
	if err := os.WriteFile(outputPath, []byte("partial"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	record := fileRecord{
		fileID:   fileID,
		metadata: makeTestFileMetadataWithKey(t, int64(len(plaintext)), wrappedFileKey),
	}
	backup := &Backup{
		directory: backupDirectory,
		keybag: &keybag{classKeys: map[uint32]*classKey{
			1: {class: 1, key: keyEncryptionKey},
		}},
	}

	status, err := backup.extractRecord(record, outputPath)
	if err != nil {
		t.Fatalf("extractRecord() error = %v", err)
	}
	if status != extractionStatusRepaired {
		t.Fatalf("extractRecord() status = %v, want %v", status, extractionStatusRepaired)
	}
	assertFileContents(t, outputPath, plaintext)
}

func TestExtractRecordPreservesMismatchWhenRepairFails(t *testing.T) {
	t.Parallel()

	keyEncryptionKey, wrappedFileKey, _ := testEncryptionKeys(t)
	fileID := strings.Repeat("c", 40)
	backupDirectory := t.TempDir()
	encryptedDirectory := filepath.Join(backupDirectory, fileID[:2])
	if err := os.Mkdir(encryptedDirectory, 0o700); err != nil {
		t.Fatalf("os.Mkdir() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(encryptedDirectory, fileID), []byte("invalid"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	original := []byte("existing file remains safe")
	outputDirectory := t.TempDir()
	outputPath := filepath.Join(outputDirectory, "IMG_0003.JPG")
	if err := os.WriteFile(outputPath, original, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	record := fileRecord{
		fileID:   fileID,
		metadata: makeTestFileMetadataWithKey(t, int64(len(original)+10), wrappedFileKey),
	}
	backup := &Backup{
		directory: backupDirectory,
		keybag: &keybag{classKeys: map[uint32]*classKey{
			1: {class: 1, key: keyEncryptionKey},
		}},
	}

	if _, err := backup.extractRecord(record, outputPath); err == nil {
		t.Fatal("extractRecord() error = nil, want invalid encrypted-file error")
	}
	assertFileContents(t, outputPath, original)
	entries, err := os.ReadDir(outputDirectory)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(outputPath) {
		t.Fatalf("repair failure left unexpected files: %v", entries)
	}
}

func TestExtractRecordRejectsWrongSizedUnencryptedSource(t *testing.T) {
	t.Parallel()

	backup := &Backup{directory: t.TempDir()}
	record := fileRecord{fileID: strings.Repeat("a", 40)}
	inputDirectory := filepath.Join(backup.directory, record.fileID[:2])
	if err := os.Mkdir(inputDirectory, 0o700); err != nil {
		t.Fatalf("create backup file directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputDirectory, record.fileID), []byte("partial"), 0o600); err != nil {
		t.Fatalf("write incomplete backup file: %v", err)
	}
	outputDirectory := t.TempDir()
	outputPath := filepath.Join(outputDirectory, "IMG_0001.JPG")
	original := []byte("existing output")
	if err := os.WriteFile(outputPath, original, 0o600); err != nil {
		t.Fatalf("write existing output: %v", err)
	}
	_, err := backup.extractRecordWithMetadata(record, fileMetadata{size: 30}, outputPath)
	if err == nil || !strings.Contains(err.Error(), "copied 7 bytes, expected 30") {
		t.Fatalf("extractRecordWithMetadata() error = %v, want copied-size mismatch", err)
	}
	assertFileContents(t, outputPath, original)
	entries, err := os.ReadDir(outputDirectory)
	if err != nil {
		t.Fatalf("read output directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(outputPath) {
		t.Fatalf("repair failure left unexpected files: %v", entries)
	}
}

func TestReplaceOutputFilePreservesOriginalWhenRepairIsMissing(t *testing.T) {
	t.Parallel()

	outputDirectory := t.TempDir()
	outputPath := filepath.Join(outputDirectory, "IMG_0004.JPG")
	original := []byte("original camera data")
	if err := os.WriteFile(outputPath, original, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	missingReplacement := filepath.Join(outputDirectory, "missing-replacement")

	if err := replaceOutputFile(
		missingReplacement,
		outputPath,
		int64(len(original)),
		time.Time{},
		time.Time{},
	); err == nil {
		t.Fatal("replaceOutputFile() error = nil, want missing replacement error")
	}
	assertFileContents(t, outputPath, original)
	entries, err := os.ReadDir(outputDirectory)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(outputPath) {
		t.Fatalf("failed replacement left unexpected files: %v", entries)
	}
}

func TestCopyReplacementFileReplacesExistingContents(t *testing.T) {
	t.Parallel()

	outputDirectory := t.TempDir()
	replacementPath := filepath.Join(outputDirectory, "validated-repair")
	replacement := []byte("validated replacement camera data")
	if err := os.WriteFile(replacementPath, replacement, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	outputPath := filepath.Join(outputDirectory, "IMG_0004.JPG")
	if err := os.WriteFile(outputPath, []byte("wrong size"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if err := copyReplacementFile(
		replacementPath,
		outputPath,
		int64(len(replacement)),
		time.Time{},
		time.Time{},
	); err != nil {
		t.Fatalf("copyReplacementFile() error = %v", err)
	}
	assertFileContents(t, outputPath, replacement)
}

func TestExtractRecordRestoresExistingFileModificationTime(t *testing.T) {
	t.Parallel()

	original := []byte("already extracted camera data")
	outputPath := filepath.Join(t.TempDir(), "IMG_0005.JPG")
	if err := os.WriteFile(outputPath, original, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	modifiedAt := time.Date(2019, time.April, 5, 6, 7, 8, 0, time.UTC)
	record := fileRecord{fileID: strings.Repeat("a", 40)}
	metadata := fileMetadata{
		size:       int64(len(original)),
		modifiedAt: modifiedAt,
	}

	status, err := (&Backup{}).extractRecordWithMetadata(record, metadata, outputPath)
	if err != nil {
		t.Fatalf("extractRecordWithMetadata() error = %v", err)
	}
	if status != extractionStatusVerified {
		t.Fatalf("extractRecordWithMetadata() status = %v, want %v", status, extractionStatusVerified)
	}
	assertFileContents(t, outputPath, original)
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}
	if !info.ModTime().Equal(modifiedAt) {
		t.Fatalf("modification time = %v, want %v", info.ModTime(), modifiedAt)
	}
}

func TestExtractFilesReportsExpectedAndVerifiedCounts(t *testing.T) {
	t.Parallel()

	database := openTestManifestDatabase(t, ":memory:")
	metadata := makeTestFileMetadata(t, 5)
	if _, err := database.Exec(
		"INSERT INTO Files (fileID, domain, relativePath, file, flags) VALUES (?, ?, ?, ?, 1)",
		strings.Repeat("c", 40),
		"CameraRollDomain",
		"Media/DCIM/100APPLE/IMG_0003.JPG",
		metadata,
	); err != nil {
		t.Fatalf("insert manifest record: %v", err)
	}
	outputDirectory := t.TempDir()
	outputPath := filepath.Join(outputDirectory, "IMG_0003.JPG")
	if err := os.WriteFile(outputPath, []byte("12345"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var updates [][2]int
	summary, err := (&Backup{manifestDatabase: database}).ExtractFilesWithProgress(
		"Media/DCIM/%APPLE/IMG%.%",
		"CameraRollDomain",
		outputDirectory,
		func(processed, expected int) {
			updates = append(updates, [2]int{processed, expected})
		},
	)
	if err != nil {
		t.Fatalf("ExtractFiles() error = %v", err)
	}
	if summary.Expected != 1 || summary.Verified != 1 || summary.Extracted != 0 || summary.Repaired != 0 {
		t.Fatalf("ExtractFiles() summary = %+v, want one expected and verified file", summary)
	}
	if len(updates) != 2 || updates[0] != [2]int{0, 1} || updates[1] != [2]int{1, 1} {
		t.Fatalf("ExtractFilesWithProgress() updates = %v, want [(0,1) (1,1)]", updates)
	}
}

func TestExtractFilesEmitsDebugEvents(t *testing.T) {
	t.Parallel()

	database := openTestManifestDatabase(t, ":memory:")
	metadata := makeTestFileMetadata(t, 5)
	if _, err := database.Exec(
		"INSERT INTO Files (fileID, domain, relativePath, file, flags) VALUES (?, ?, ?, ?, 1)",
		strings.Repeat("d", 40),
		"CameraRollDomain",
		"Media/DCIM/100APPLE/IMG_0004.JPG",
		metadata,
	); err != nil {
		t.Fatalf("insert manifest record: %v", err)
	}
	outputDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(outputDirectory, "IMG_0004.JPG"), []byte("12345"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	var events []ExtractionDebugEvent

	summary, err := (&Backup{manifestDatabase: database}).ExtractFilesWithProgressAndDebug(
		"Media/DCIM/%APPLE/IMG%.%",
		"CameraRollDomain",
		outputDirectory,
		nil,
		func(event ExtractionDebugEvent) {
			events = append(events, event)
		},
	)
	if err != nil {
		t.Fatalf("ExtractFilesWithProgressAndDebug() error = %v", err)
	}
	if summary.Verified != 1 {
		t.Fatalf("ExtractFilesWithProgressAndDebug() summary = %+v, want one verified file", summary)
	}
	if len(events) != 2 {
		t.Fatalf("debug events = %v, want start and complete events", events)
	}
	if events[0].Phase != "start" || events[1].Phase != "complete" || events[1].Action != "verified" {
		t.Fatalf("debug events = %v, want start followed by verified completion", events)
	}
	if events[1].ExpectedSize != 5 || events[1].OutputFilename != "IMG_0004.JPG" {
		t.Fatalf("complete debug event = %+v", events[1])
	}
}

func TestExtractFilesContinuesAfterFileFailure(t *testing.T) {
	t.Parallel()

	database := openTestManifestDatabase(t, ":memory:")
	metadata := makeTestFileMetadata(t, 5)
	for index, relativePath := range []string{
		"Media/DCIM/100APPLE/IMG_0005.JPG",
		"Media/DCIM/100APPLE/IMG_0006.JPG",
	} {
		fileID := strings.Repeat(string(rune('a'+index)), 40)
		if _, err := database.Exec(
			"INSERT INTO Files (fileID, domain, relativePath, file, flags) VALUES (?, ?, ?, ?, 1)",
			fileID,
			"CameraRollDomain",
			relativePath,
			metadata,
		); err != nil {
			t.Fatalf("insert manifest record: %v", err)
		}
	}
	outputDirectory := t.TempDir()
	if err := os.Mkdir(filepath.Join(outputDirectory, "IMG_0005.JPG"), 0o700); err != nil {
		t.Fatalf("os.Mkdir() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDirectory, "IMG_0006.JPG"), []byte("12345"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	summary, err := (&Backup{manifestDatabase: database}).ExtractFiles(
		"Media/DCIM/%APPLE/IMG%.%",
		"CameraRollDomain",
		outputDirectory,
	)
	if err == nil {
		t.Fatal("ExtractFiles() error = nil, want one file failure")
	}
	if summary.Expected != 2 || summary.Failed != 1 || summary.Verified != 1 {
		t.Fatalf("ExtractFiles() summary = %+v, want one failure and one verified file", summary)
	}
}

func TestExtractFilesSuffixesFlattenedFilenameCollisions(t *testing.T) {
	t.Parallel()

	database := openTestManifestDatabase(t, ":memory:")
	metadata := makeTestFileMetadata(t, 5)
	for index, relativePath := range []string{
		"Media/DCIM/100APPLE/IMG_0004.JPG",
		"Media/DCIM/101APPLE/IMG_0004.JPG",
		"Media/DCIM/102APPLE/IMG_0004.JPG",
	} {
		fileID := strings.Repeat(string(rune('d'+index)), 40)
		if _, err := database.Exec(
			"INSERT INTO Files (fileID, domain, relativePath, file, flags) VALUES (?, ?, ?, ?, 1)",
			fileID,
			"CameraRollDomain",
			relativePath,
			metadata,
		); err != nil {
			t.Fatalf("insert manifest record: %v", err)
		}
	}
	outputDirectory := t.TempDir()
	original := []byte("12345")
	for _, filename := range []string{"IMG_0004.JPG", "IMG_0004_2.JPG", "IMG_0004_3.JPG"} {
		if err := os.WriteFile(filepath.Join(outputDirectory, filename), original, 0o600); err != nil {
			t.Fatalf("os.WriteFile() error = %v", err)
		}
	}

	summary, err := (&Backup{manifestDatabase: database}).ExtractFiles(
		"Media/DCIM/%APPLE/IMG%.%",
		"CameraRollDomain",
		outputDirectory,
	)
	if err != nil {
		t.Fatalf("ExtractFiles() error = %v", err)
	}
	if summary.Expected != 3 || summary.Verified != 3 || summary.Collisions != 2 {
		t.Fatalf("ExtractFiles() summary = %+v, want three verified files and two collisions", summary)
	}
}

func TestSuffixedFilename(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		filename   string
		occurrence int
		want       string
	}{
		{filename: "IMG_0001.JPG", occurrence: 1, want: "IMG_0001.JPG"},
		{filename: "IMG_0001.JPG", occurrence: 2, want: "IMG_0001_2.JPG"},
		{filename: "IMG_0001.AAE", occurrence: 3, want: "IMG_0001_3.AAE"},
	}
	for _, testCase := range testCases {
		got := suffixedFilename(testCase.filename, testCase.occurrence)
		if got != testCase.want {
			t.Errorf("suffixedFilename(%q, %d) = %q, want %q", testCase.filename, testCase.occurrence, got, testCase.want)
		}
	}
}

// makeTestFileMetadata returns valid archived metadata with the requested size.
func makeTestFileMetadata(t *testing.T, size int64) []byte {
	t.Helper()
	return makeTestFileMetadataWithKey(t, size, []byte{1})
}

// makeTestFileMetadataWithKey returns archived metadata with wrappedKey.
func makeTestFileMetadataWithKey(t *testing.T, size int64, wrappedKey []byte) []byte {
	t.Helper()

	encodedKey := append([]byte{0, 0, 0, 1}, wrappedKey...)
	archive := map[string]any{
		"$top": map[string]any{"root": plist.UID(1)},
		"$objects": []any{
			"$null",
			map[string]any{
				"Size":            size,
				"ProtectionClass": uint64(1),
				"EncryptionKey":   plist.UID(2),
			},
			map[string]any{"NS.data": encodedKey},
		},
	}
	data, err := plist.Marshal(archive, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("plist.Marshal() error = %v", err)
	}
	return data
}

// writeEncryptedTestFile writes zero-IV AES-CBC ciphertext for plaintext.
func writeEncryptedTestFile(t *testing.T, filename string, plaintext, key []byte) {
	t.Helper()

	padded := append([]byte(nil), plaintext...)
	paddingLength := aes.BlockSize - len(padded)%aes.BlockSize
	padded = append(padded, bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)...)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(encrypted, padded)
	if err := os.WriteFile(filename, encrypted, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
}

// testEncryptionKeys returns an RFC 3394 256-bit key-wrap fixture.
func testEncryptionKeys(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()

	keyEncryptionKey := mustDecodeHex(
		t,
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
	)
	wrappedFileKey := mustDecodeHex(
		t,
		"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
	)
	fileKey := mustDecodeHex(
		t,
		"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
	)
	return keyEncryptionKey, wrappedFileKey, fileKey
}

// openTestManifestDatabase creates a Files table in a fixture database.
func openTestManifestDatabase(t *testing.T, filename string) *sql.DB {
	t.Helper()

	database, err := sql.Open("sqlite", filename)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() {
		database.Close()
	})
	if _, err := database.Exec(`
		CREATE TABLE Files (
			fileID TEXT,
			domain TEXT,
			relativePath TEXT,
			file BLOB,
			flags INTEGER
		)`); err != nil {
		t.Fatalf("create Files table: %v", err)
	}
	return database
}

// assertFileContents verifies that filename still contains expected.
func assertFileContents(t *testing.T, filename string, expected []byte) {
	t.Helper()

	actual, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("file contents = %q, want %q", actual, expected)
	}
}
