package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"howett.net/plist"
	_ "modernc.org/sqlite"
)

// decryptBufferSize is the number of encrypted bytes processed per read.
const decryptBufferSize = 1024 * 1024

// fileIDPattern matches the hexadecimal identifiers used for backup files.
var fileIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// A manifest describes the encryption metadata in Manifest.plist.
type manifest struct {
	// BackupKeyBag contains the wrapped protection-class keys for the backup.
	BackupKeyBag []byte `plist:"BackupKeyBag"`
	// Date records when the backup was created.
	Date time.Time `plist:"Date"`
	// IsEncrypted reports whether the backup requires a password.
	IsEncrypted bool `plist:"IsEncrypted"`
	// ManifestKey contains the protection class and wrapped key for Manifest.db.
	ManifestKey []byte `plist:"ManifestKey"`
}

// A Backup provides access to files in an open device backup. The
// zero value is not usable; callers must create a Backup with [OpenBackup] and
// release it with [Backup.Close].
type Backup struct {
	directory        string
	keybag           *keybag
	manifestDatabase *sql.DB
	temporaryPath    string
}

// A fileRecord identifies a backup file and its archived metadata.
type fileRecord struct {
	fileID       string
	domain       string
	relativePath string
	metadata     []byte
}

// ExtractionSummary reports the outcome of a multi-file extraction pass.
type ExtractionSummary struct {
	Expected   int
	Extracted  int
	Verified   int
	Repaired   int
	Collisions int
	Failed     int
}

// ExtractionProgressFunc receives the processed and expected file counts.
type ExtractionProgressFunc func(processed, expected int)

// ExtractionDebugEvent records timing and outcome information for one file.
type ExtractionDebugEvent struct {
	Phase                  string  `json:"phase"`
	Index                  int     `json:"index"`
	Total                  int     `json:"total"`
	RelativePath           string  `json:"relative_path"`
	OutputFilename         string  `json:"output_filename"`
	Action                 string  `json:"action,omitempty"`
	ExpectedSize           int64   `json:"expected_size,omitempty"`
	MetadataMilliseconds   float64 `json:"metadata_ms,omitempty"`
	ProcessingMilliseconds float64 `json:"processing_ms,omitempty"`
	TotalMilliseconds      float64 `json:"total_ms,omitempty"`
	Error                  string  `json:"error,omitempty"`
}

// ExtractionDebugFunc receives detailed per-file debugging events.
type ExtractionDebugFunc func(event ExtractionDebugEvent)

type extractionStatus uint8

const (
	extractionStatusExtracted extractionStatus = iota
	extractionStatusVerified
	extractionStatusRepaired
)

// An existingFileMismatchError reports an existing output that does not match
// the backup metadata.
type existingFileMismatchError struct {
	filename     string
	expectedSize int64
	actualSize   int64
	reason       string
}

// Error returns a description of the existing-file mismatch.
func (mismatch *existingFileMismatchError) Error() string {
	if mismatch.reason != "" {
		return fmt.Sprintf("existing output %s %s", mismatch.filename, mismatch.reason)
	}
	return fmt.Sprintf(
		"existing output %s has size %d, expected %d",
		mismatch.filename,
		mismatch.actualSize,
		mismatch.expectedSize,
	)
}

// OpenBackup returns the backup in directory, using password to unlock it if
// it is encrypted.
func OpenBackup(directory string, password []byte) (*Backup, error) {
	cleanDirectory, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve backup directory: %w", err)
	}
	info, err := os.Stat(cleanDirectory)
	if err != nil {
		return nil, fmt.Errorf("inspect backup directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("backup path is not a directory: %s", cleanDirectory)
	}

	manifestData, err := readManifest(filepath.Join(cleanDirectory, "Manifest.plist"))
	if err != nil {
		return nil, err
	}
	return openBackupWithManifest(cleanDirectory, manifestData, password)
}

// openBackupWithManifest opens the database for the already inspected backup.
func openBackupWithManifest(directory string, manifestData manifest, password []byte) (*Backup, error) {
	manifestPath := filepath.Join(directory, "Manifest.db")
	if !manifestData.IsEncrypted {
		uri := url.URL{Scheme: "file", Path: filepath.ToSlash(manifestPath), RawQuery: "mode=ro"}
		database, err := openManifestDatabase(uri.String(), "Manifest.db")
		if err != nil {
			return nil, err
		}
		return &Backup{directory: directory, manifestDatabase: database}, nil
	}
	if len(manifestData.BackupKeyBag) == 0 || len(manifestData.ManifestKey) < 5 {
		return nil, errors.New("encrypted backup manifest lacks key material")
	}

	bag, err := parseKeybag(manifestData.BackupKeyBag)
	if err != nil {
		return nil, fmt.Errorf("parse backup keybag: %w", err)
	}
	if err := bag.unlock(password); err != nil {
		bag.close()
		return nil, err
	}

	manifestClass := binary.LittleEndian.Uint32(manifestData.ManifestKey[:4])
	manifestKey, err := bag.unwrapKeyForClass(manifestClass, manifestData.ManifestKey[4:])
	if err != nil {
		bag.close()
		return nil, fmt.Errorf("unwrap manifest database key: %w", err)
	}
	defer clear(manifestKey)

	temporaryFile, err := os.CreateTemp("", "ios-files-manifest-*.db")
	if err != nil {
		bag.close()
		return nil, fmt.Errorf("create temporary manifest database: %w", err)
	}
	temporaryPath := temporaryFile.Name()
	cleanup := func() {
		temporaryFile.Close()
		os.Remove(temporaryPath)
		bag.close()
	}

	if err := decryptCBCFile(manifestPath, temporaryFile, manifestKey, nil); err != nil {
		cleanup()
		return nil, fmt.Errorf("decrypt Manifest.db: %w", err)
	}
	if err := temporaryFile.Close(); err != nil {
		cleanup()
		return nil, fmt.Errorf("close temporary manifest database: %w", err)
	}

	database, err := openManifestDatabase(temporaryPath, "decrypted Manifest.db")
	if err != nil {
		cleanup()
		return nil, err
	}
	return &Backup{
		directory:        directory,
		keybag:           bag,
		manifestDatabase: database,
		temporaryPath:    temporaryPath,
	}, nil
}

// openManifestDatabase opens SQLite and checks that the manifest has file rows.
func openManifestDatabase(dsn, description string) (*sql.DB, error) {
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", description, err)
	}
	database.SetMaxOpenConns(1)
	var fileCount int
	if err := database.QueryRow("SELECT count(*) FROM Files").Scan(&fileCount); err != nil {
		database.Close()
		return nil, fmt.Errorf("validate %s: %w", description, err)
	}
	if fileCount == 0 {
		database.Close()
		return nil, fmt.Errorf("%s contains no files", description)
	}
	return database, nil
}

// Close releases the manifest database and cleans up any temporary file and keys.
func (backup *Backup) Close() error {
	var closeError error
	if backup.manifestDatabase != nil {
		closeError = backup.manifestDatabase.Close()
		backup.manifestDatabase = nil
	}
	if backup.temporaryPath != "" {
		if err := os.Remove(backup.temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) && closeError == nil {
			closeError = err
		}
		backup.temporaryPath = ""
	}
	if backup.keybag != nil {
		backup.keybag.close()
		backup.keybag = nil
	}
	return closeError
}

// ExtractFile writes the first file matching relativePath and the SQL
// LIKE domainPattern to outputFile. A matching output is verified, while a
// wrong-sized regular file is safely replaced.
func (backup *Backup) ExtractFile(relativePath, domainPattern, outputFile string) error {
	const query = `
		SELECT fileID, domain, relativePath, file
		FROM Files
		WHERE relativePath = ? AND domain LIKE ? AND flags = 1
		ORDER BY domain, relativePath
		LIMIT 1`

	var record fileRecord
	err := backup.manifestDatabase.QueryRowContext(
		context.Background(),
		query,
		relativePath,
		domainPattern,
	).Scan(&record.fileID, &record.domain, &record.relativePath, &record.metadata)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("file not found in backup: %s", relativePath)
	}
	if err != nil {
		return fmt.Errorf("query Manifest.db: %w", err)
	}
	_, err = backup.extractRecord(record, outputFile)
	return err
}

// ExtractFiles writes all files matching the SQL LIKE path and domain
// patterns to outputDirectory. Existing regular files with the expected size
// are verified without being rewritten. Wrong-sized regular files are replaced
// atomically, and duplicate base filenames receive numeric suffixes.
func (backup *Backup) ExtractFiles(
	relativePathPattern,
	domainPattern,
	outputDirectory string,
) (ExtractionSummary, error) {
	return backup.extractFiles(relativePathPattern, domainPattern, outputDirectory, nil, nil)
}

// ExtractFilesWithProgress behaves like [Backup.ExtractFiles] and calls
// progress before processing starts and after each file has been processed.
func (backup *Backup) ExtractFilesWithProgress(
	relativePathPattern,
	domainPattern,
	outputDirectory string,
	progress ExtractionProgressFunc,
) (ExtractionSummary, error) {
	return backup.extractFiles(relativePathPattern, domainPattern, outputDirectory, progress, nil)
}

// ExtractFilesWithProgressAndDebug behaves like [Backup.ExtractFiles] and
// reports both progress and per-file debugging events.
func (backup *Backup) ExtractFilesWithProgressAndDebug(
	relativePathPattern,
	domainPattern,
	outputDirectory string,
	progress ExtractionProgressFunc,
	debug ExtractionDebugFunc,
) (ExtractionSummary, error) {
	return backup.extractFiles(relativePathPattern, domainPattern, outputDirectory, progress, debug)
}

// extractFiles implements multi-file extraction with optional progress updates.
func (backup *Backup) extractFiles(
	relativePathPattern,
	domainPattern,
	outputDirectory string,
	progress ExtractionProgressFunc,
	debug ExtractionDebugFunc,
) (ExtractionSummary, error) {
	const countQuery = `
		SELECT count(*)
		FROM Files
		WHERE relativePath LIKE ? AND domain LIKE ? AND flags = 1`
	const query = `
		SELECT fileID, domain, relativePath, file
		FROM Files
		WHERE relativePath LIKE ? AND domain LIKE ? AND flags = 1
		ORDER BY domain, relativePath`

	var summary ExtractionSummary
	if err := backup.manifestDatabase.QueryRowContext(
		context.Background(),
		countQuery,
		relativePathPattern,
		domainPattern,
	).Scan(&summary.Expected); err != nil {
		return summary, fmt.Errorf("count matching Manifest.db rows: %w", err)
	}
	if progress != nil {
		progress(0, summary.Expected)
	}

	rows, err := backup.manifestDatabase.QueryContext(
		context.Background(),
		query,
		relativePathPattern,
		domainPattern,
	)
	if err != nil {
		return summary, fmt.Errorf("query Manifest.db: %w", err)
	}
	defer rows.Close()

	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return summary, fmt.Errorf("create output directory: %w", err)
	}

	filenameOccurrences := make(map[string]int, summary.Expected)
	assignedOutputs := make(map[string]struct{}, summary.Expected)
	var firstExtractionError error
	processed := 0
	advanceProgress := func() {
		processed++
		if progress != nil {
			progress(processed, summary.Expected)
		}
	}
	for rows.Next() {
		var record fileRecord
		if err := rows.Scan(&record.fileID, &record.domain, &record.relativePath, &record.metadata); err != nil {
			return summary, fmt.Errorf("read Manifest.db row: %w", err)
		}
		baseFilename := path.Base(record.relativePath)
		if baseFilename == "." || baseFilename == "/" || baseFilename == "" {
			return summary, fmt.Errorf("invalid backup relative path: %q", record.relativePath)
		}

		occurrence := filenameOccurrences[baseFilename] + 1
		filename := suffixedFilename(baseFilename, occurrence)
		_, alreadyAssigned := assignedOutputs[strings.ToLower(filename)]
		for alreadyAssigned {
			occurrence++
			filename = suffixedFilename(baseFilename, occurrence)
			_, alreadyAssigned = assignedOutputs[strings.ToLower(filename)]
		}
		filenameOccurrences[baseFilename] = occurrence
		assignedOutputs[strings.ToLower(filename)] = struct{}{}
		if occurrence > 1 {
			summary.Collisions++
		}

		index := processed + 1
		recordStarted := time.Now()
		if debug != nil {
			debug(ExtractionDebugEvent{
				Phase:          "start",
				Index:          index,
				Total:          summary.Expected,
				RelativePath:   record.relativePath,
				OutputFilename: filename,
			})
		}
		metadataStarted := time.Now()
		metadata, err := parseFileMetadata(record.metadata, backup.keybag != nil)
		metadataDuration := time.Since(metadataStarted)
		if err != nil {
			summary.Failed++
			if firstExtractionError == nil {
				firstExtractionError = fmt.Errorf("parse metadata for %s: %w", record.relativePath, err)
			}
			if debug != nil {
				debug(ExtractionDebugEvent{
					Phase:                "complete",
					Index:                index,
					Total:                summary.Expected,
					RelativePath:         record.relativePath,
					OutputFilename:       filename,
					Action:               "failed",
					MetadataMilliseconds: durationMilliseconds(metadataDuration),
					TotalMilliseconds:    durationMilliseconds(time.Since(recordStarted)),
					Error:                err.Error(),
				})
			}
			advanceProgress()
			continue
		}

		processingStarted := time.Now()
		status, err := backup.extractRecordWithMetadata(
			record,
			metadata,
			filepath.Join(outputDirectory, filename),
		)
		processingDuration := time.Since(processingStarted)
		if err != nil {
			summary.Failed++
			if firstExtractionError == nil {
				firstExtractionError = fmt.Errorf("extract %s: %w", record.relativePath, err)
			}
			if debug != nil {
				debug(ExtractionDebugEvent{
					Phase:                  "complete",
					Index:                  index,
					Total:                  summary.Expected,
					RelativePath:           record.relativePath,
					OutputFilename:         filename,
					Action:                 "failed",
					ExpectedSize:           metadata.size,
					MetadataMilliseconds:   durationMilliseconds(metadataDuration),
					ProcessingMilliseconds: durationMilliseconds(processingDuration),
					TotalMilliseconds:      durationMilliseconds(time.Since(recordStarted)),
					Error:                  err.Error(),
				})
			}
			advanceProgress()
			continue
		}
		action := ""
		switch status {
		case extractionStatusExtracted:
			summary.Extracted++
			action = "extracted"
		case extractionStatusVerified:
			summary.Verified++
			action = "verified"
		case extractionStatusRepaired:
			summary.Repaired++
			action = "repaired"
		}
		if debug != nil {
			debug(ExtractionDebugEvent{
				Phase:                  "complete",
				Index:                  index,
				Total:                  summary.Expected,
				RelativePath:           record.relativePath,
				OutputFilename:         filename,
				Action:                 action,
				ExpectedSize:           metadata.size,
				MetadataMilliseconds:   durationMilliseconds(metadataDuration),
				ProcessingMilliseconds: durationMilliseconds(processingDuration),
				TotalMilliseconds:      durationMilliseconds(time.Since(recordStarted)),
			})
		}
		advanceProgress()
	}
	if err := rows.Err(); err != nil {
		return summary, fmt.Errorf("iterate Manifest.db rows: %w", err)
	}
	if firstExtractionError != nil {
		return summary, fmt.Errorf(
			"%d files failed during extraction or repair; first failure: %w",
			summary.Failed,
			firstExtractionError,
		)
	}
	return summary, nil
}

// durationMilliseconds returns duration as fractional milliseconds.
func durationMilliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}

// suffixedFilename adds a numeric suffix before the extension for occurrences
// after the first, such as IMG_0001_2.JPG.
func suffixedFilename(filename string, occurrence int) string {
	if occurrence <= 1 {
		return filename
	}
	extension := path.Ext(filename)
	stem := strings.TrimSuffix(filename, extension)
	return fmt.Sprintf("%s_%d%s", stem, occurrence, extension)
}

// extractRecord writes the contents represented by record to
// outputFile and preserves the recorded creation and modification times when
// available. An existing output is verified by size. A wrong-sized regular
// file is rebuilt in a temporary file and safely swapped in after validation.
func (backup *Backup) extractRecord(record fileRecord, outputFile string) (extractionStatus, error) {
	if !fileIDPattern.MatchString(record.fileID) {
		return extractionStatusExtracted, fmt.Errorf("invalid backup file ID: %q", record.fileID)
	}
	metadata, err := parseFileMetadata(record.metadata, backup.keybag != nil)
	if err != nil {
		return extractionStatusExtracted, err
	}
	return backup.extractRecordWithMetadata(record, metadata, outputFile)
}

// extractRecordWithMetadata extracts or verifies record using parsed metadata.
func (backup *Backup) extractRecordWithMetadata(
	record fileRecord,
	metadata fileMetadata,
	outputFile string,
) (extractionStatus, error) {
	if !fileIDPattern.MatchString(record.fileID) {
		return extractionStatusExtracted, fmt.Errorf("invalid backup file ID: %q", record.fileID)
	}
	exists, err := verifyExistingFile(outputFile, metadata.size)
	repairExisting := false
	if err != nil {
		var mismatch *existingFileMismatchError
		if !errors.As(err, &mismatch) || mismatch.reason != "" {
			return extractionStatusExtracted, err
		}
		repairExisting = true
	}
	if exists && !repairExisting {
		if err := applyFileTimestamps(outputFile, metadata.createdAt, metadata.modifiedAt); err != nil {
			return extractionStatusExtracted, fmt.Errorf("restore existing output timestamps: %w", err)
		}
		return extractionStatusVerified, nil
	}
	var fileKey []byte
	if backup.keybag != nil {
		fileKey, err = backup.keybag.unwrapKeyForClass(metadata.protectionClass, metadata.encryptionKey)
		if err != nil {
			return extractionStatusExtracted, fmt.Errorf("unwrap file key: %w", err)
		}
		defer clear(fileKey)
	}

	if err := os.MkdirAll(filepath.Dir(outputFile), 0o755); err != nil {
		return extractionStatusExtracted, fmt.Errorf("create output directory: %w", err)
	}
	writePath := outputFile
	var output *os.File
	if repairExisting {
		output, err = os.CreateTemp(filepath.Dir(outputFile), ".ios-files-repair-*")
		if err == nil {
			writePath = output.Name()
		}
	} else {
		output, err = os.OpenFile(outputFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	}
	if err != nil {
		return extractionStatusExtracted, fmt.Errorf("create output file: %w", err)
	}
	succeeded := false
	defer func() {
		output.Close()
		if !succeeded {
			os.Remove(writePath)
		}
	}()

	inputPath := filepath.Join(backup.directory, record.fileID[:2], record.fileID)
	if backup.keybag != nil {
		err = decryptCBCFile(inputPath, output, fileKey, &metadata.size)
	} else {
		err = copyPlaintextFile(inputPath, output, metadata.size)
	}
	if err != nil {
		return extractionStatusExtracted, err
	}
	if err := output.Close(); err != nil {
		return extractionStatusExtracted, fmt.Errorf("close output file: %w", err)
	}
	if err := applyFileTimestamps(writePath, metadata.createdAt, metadata.modifiedAt); err != nil {
		return extractionStatusExtracted, err
	}
	if repairExisting {
		if err := replaceOutputFile(
			writePath,
			outputFile,
			metadata.size,
			metadata.createdAt,
			metadata.modifiedAt,
		); err != nil {
			return extractionStatusExtracted, fmt.Errorf("replace mismatched output file: %w", err)
		}
	}
	succeeded = true
	if repairExisting {
		return extractionStatusRepaired, nil
	}
	return extractionStatusExtracted, nil
}

// replaceOutputFile installs a fully validated repair on filesystems such as
// SMB that may reject rename-over-existing operations. If a rename into the
// vacant destination still fails, it falls back to a streamed file copy.
func replaceOutputFile(
	replacementPath,
	outputFile string,
	expectedSize int64,
	createdAt,
	modifiedAt time.Time,
) error {
	replacement, err := os.Open(replacementPath)
	if err != nil {
		return fmt.Errorf("open validated repair: %w", err)
	}
	if err := replacement.Close(); err != nil {
		return fmt.Errorf("close validated repair: %w", err)
	}
	if err := os.Remove(outputFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove mismatched output: %w", err)
	}

	renameError := os.Rename(replacementPath, outputFile)
	if renameError == nil {
		return nil
	}

	// Some SMB servers report an error after completing the rename. Confirm the
	// destination before attempting the copy fallback.
	if outputInfo, err := os.Stat(outputFile); err == nil && outputInfo.Size() == expectedSize {
		if _, err := os.Stat(replacementPath); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}

	if err := copyReplacementFile(
		replacementPath,
		outputFile,
		expectedSize,
		createdAt,
		modifiedAt,
	); err != nil {
		return fmt.Errorf("rename repair: %v; copy fallback: %w", renameError, err)
	}
	if err := os.Remove(replacementPath); err != nil {
		return fmt.Errorf("remove copied repair temporary file: %w", err)
	}
	return nil
}

// copyReplacementFile copies a validated repair into outputFile. A failed copy
// removes its partial destination so a later pass retries it as a missing file.
func copyReplacementFile(
	replacementPath,
	outputFile string,
	expectedSize int64,
	createdAt,
	modifiedAt time.Time,
) error {
	input, err := os.Open(replacementPath)
	if err != nil {
		return fmt.Errorf("open validated repair: %w", err)
	}
	defer input.Close()

	output, err := os.OpenFile(outputFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create repaired output: %w", err)
	}
	succeeded := false
	defer func() {
		output.Close()
		if !succeeded {
			os.Remove(outputFile)
		}
	}()

	written, err := io.Copy(output, input)
	if err != nil {
		return fmt.Errorf("copy validated repair: %w", err)
	}
	if written != expectedSize {
		return fmt.Errorf("copied %d repair bytes, expected %d", written, expectedSize)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close repaired output: %w", err)
	}
	if err := applyFileTimestamps(outputFile, createdAt, modifiedAt); err != nil {
		return fmt.Errorf("restore repaired output timestamps: %w", err)
	}
	succeeded = true
	return nil
}

// verifyExistingFile reports whether filename already exists with the expected
// logical byte size. Any existing non-matching path is returned as an error.
func verifyExistingFile(filename string, expectedSize int64) (bool, error) {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect existing output: %w", err)
	}
	if !info.Mode().IsRegular() {
		return true, &existingFileMismatchError{
			filename: filename,
			reason:   "is not a regular file",
		}
	}
	if info.Size() != expectedSize {
		return true, &existingFileMismatchError{
			filename:     filename,
			expectedSize: expectedSize,
			actualSize:   info.Size(),
		}
	}
	return true, nil
}

// readManifest returns the backup manifest decoded from filename.
func readManifest(filename string) (manifest, error) {
	input, err := os.Open(filename)
	if err != nil {
		return manifest{}, fmt.Errorf("open Manifest.plist: %w", err)
	}
	defer input.Close()

	var value manifest
	if err := plist.NewDecoder(input).Decode(&value); err != nil {
		return manifest{}, fmt.Errorf("decode Manifest.plist: %w", err)
	}
	return value, nil
}

// copyPlaintextFile copies an unencrypted backup file and checks its byte count.
func copyPlaintextFile(inputPath string, output io.Writer, expectedSize int64) error {
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open backup file: %w", err)
	}
	defer input.Close()

	written, err := io.Copy(output, input)
	if err != nil {
		return fmt.Errorf("copy backup file: %w", err)
	}
	if written != expectedSize {
		return fmt.Errorf("copied %d bytes, expected %d", written, expectedSize)
	}
	return nil
}

// decryptCBCFile writes the zero-IV AES-CBC plaintext from inputPath to output.
// When expectedSize is non-nil, it limits and validates the plaintext length.
func decryptCBCFile(inputPath string, output io.Writer, key []byte, expectedSize *int64) error {
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open encrypted file: %w", err)
	}
	defer input.Close()

	info, err := input.Stat()
	if err != nil {
		return fmt.Errorf("inspect encrypted file: %w", err)
	}
	if info.Size() == 0 || info.Size()%aes.BlockSize != 0 {
		return fmt.Errorf("encrypted file size %d is not a positive AES block multiple", info.Size())
	}
	if expectedSize != nil && (*expectedSize < 0 || *expectedSize > info.Size()) {
		return fmt.Errorf("invalid expected plaintext size %d", *expectedSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create AES cipher: %w", err)
	}
	decrypter := cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize))
	buffer := make([]byte, decryptBufferSize)
	remaining := info.Size()
	written := int64(0)

	for remaining > 0 {
		readSize := int64(len(buffer))
		if remaining < readSize {
			readSize = remaining
		}
		chunk := buffer[:readSize]
		if _, err := io.ReadFull(input, chunk); err != nil {
			return fmt.Errorf("read encrypted file: %w", err)
		}
		decrypter.CryptBlocks(chunk, chunk)

		writeSize := len(chunk)
		if expectedSize != nil {
			plainRemaining := *expectedSize - written
			if plainRemaining <= 0 {
				writeSize = 0
			} else if int64(writeSize) > plainRemaining {
				writeSize = int(plainRemaining)
			}
		}
		if writeSize > 0 {
			count, err := output.Write(chunk[:writeSize])
			if err != nil {
				return fmt.Errorf("write decrypted file: %w", err)
			}
			if count != writeSize {
				return io.ErrShortWrite
			}
			written += int64(count)
		}
		remaining -= readSize
	}

	if expectedSize != nil && written != *expectedSize {
		return fmt.Errorf("decrypted %d bytes, expected %d", written, *expectedSize)
	}
	return nil
}
