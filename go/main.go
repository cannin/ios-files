package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
)

// These constants define built-in extraction targets and command defaults.
const (
	callHistoryRelativePath = "Library/CallHistoryDB/CallHistory.storedata"
	cameraRollPathPattern   = "Media/DCIM/%APPLE/IMG%.%"
	cameraRollDomainPattern = "CameraRollDomain"
	defaultBackupDirectory  = "~/Library/Application Support/MobileSync/Backup"
	defaultOutputDirectory  = "output"
)

// A config contains the validated settings for one command invocation.
type config struct {
	backupPath         string
	outputPath         string
	passwordFile       string
	extractCallHistory bool
	extractCameraRoll  bool
	debug              bool
}

// main runs the ios-files command and reports fatal errors to standard error.
func main() {
	commandStarted := time.Now()
	err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	fmt.Fprintf(
		os.Stdout,
		"Total command time: %s\n",
		time.Since(commandStarted).Round(time.Millisecond),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// run performs the extraction requested by args. It displays usage and returns
// without extracting files when args is empty or requests help.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	// Treat an empty invocation like -h so the program does not start an
	// extraction using only default values.
	if len(args) == 0 {
		args = []string{"-h"}
	}

	cfg, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	selectedBackup, err := resolveBackupDirectory(cfg.backupPath)
	if err != nil {
		return err
	}
	cfg.backupPath = selectedBackup
	fmt.Fprintf(stdout, "Using backup: %s\n", cfg.backupPath)

	manifestData, err := readManifest(filepath.Join(cfg.backupPath, "Manifest.plist"))
	if err != nil {
		return err
	}
	var password []byte
	if manifestData.IsEncrypted {
		password, err = readPassword(cfg.passwordFile, stdin, stderr)
		if err != nil {
			return fmt.Errorf("read backup password: %w", err)
		}
		defer clear(password)
		fmt.Fprintln(stdout, "Opening and unlocking the encrypted backup...")
	} else {
		fmt.Fprintln(stdout, "Opening the unencrypted backup...")
	}

	backup, err := openBackupWithManifest(cfg.backupPath, manifestData, password)
	if err != nil {
		return err
	}
	defer backup.Close()
	if err := os.MkdirAll(cfg.outputPath, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	if cfg.extractCallHistory {
		outputFile := filepath.Join(cfg.outputPath, "call_history.sqlite")
		fmt.Fprintf(stdout, "Extracting call history to %s\n", outputFile)
		if err := backup.ExtractFile(callHistoryRelativePath, "%", outputFile); err != nil {
			return fmt.Errorf("extract call history: %w", err)
		}
	}

	if cfg.extractCameraRoll {
		outputDirectory := filepath.Join(cfg.outputPath, "camera_roll")
		fmt.Fprintf(stdout, "Checking and extracting camera roll to %s\n", outputDirectory)
		progress := newProgressDisplay(stdout)
		var debugLog *extractionDebugLog
		var debugFunc ExtractionDebugFunc
		if cfg.debug {
			debugLog, err = newExtractionDebugLog()
			if err != nil {
				return fmt.Errorf("create extraction debug log: %w", err)
			}
			defer debugLog.Close()
			debugFunc = debugLog.Record
			fmt.Fprintf(stderr, "Extraction debug log: %s\n", debugLog.Filename())
		}
		summary, err := backup.ExtractFilesWithProgressAndDebug(
			cameraRollPathPattern,
			cameraRollDomainPattern,
			outputDirectory,
			progress.Update,
			debugFunc,
		)
		progress.Finish()
		fmt.Fprintf(
			stdout,
			"Camera-roll files: %d expected, %d verified existing, %d extracted, %d repaired size mismatches, %d suffixed filename collisions, %d failed\n",
			summary.Expected,
			summary.Verified,
			summary.Extracted,
			summary.Repaired,
			summary.Collisions,
			summary.Failed,
		)
		if err != nil {
			return fmt.Errorf("extract camera roll: %w", err)
		}
	}

	fmt.Fprintln(stdout, "Extraction complete.")
	return nil
}

// parseFlags returns the command configuration represented by args. Diagnostic
// and usage text is written to stderr.
func parseFlags(args []string, stderr io.Writer) (config, error) {
	var cfg config
	flags := flag.NewFlagSet("ios-files", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&cfg.backupPath, "b", defaultBackupDirectory, "device backup directory or parent backup root")
	flags.StringVar(&cfg.backupPath, "backup", defaultBackupDirectory, "device backup directory or parent backup root")
	flags.StringVar(&cfg.outputPath, "o", defaultOutputDirectory, "output directory")
	flags.StringVar(&cfg.outputPath, "output", defaultOutputDirectory, "output directory")
	flags.StringVar(&cfg.outputPath, "output-dir", defaultOutputDirectory, "output directory")
	passwordHelp := "encrypted backup password file, or - for stdin (default: secure interactive prompt)"
	flags.StringVar(&cfg.passwordFile, "p", "", passwordHelp)
	flags.StringVar(&cfg.passwordFile, "password-file", "", passwordHelp)
	flags.BoolVar(&cfg.extractCallHistory, "c", false, "extract call history")
	flags.BoolVar(&cfg.extractCallHistory, "call-history", false, "extract call history")
	flags.BoolVar(&cfg.extractCameraRoll, "r", true, "extract camera roll")
	flags.BoolVar(&cfg.extractCameraRoll, "camera-roll", true, "extract camera roll")
	flags.BoolVar(&cfg.debug, "d", true, "write detailed extraction timing diagnostics")
	flags.BoolVar(&cfg.debug, "debug", true, "write detailed extraction timing diagnostics")
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: ios-files [options]\n\nOptions:\n")
		flags.PrintDefaults()
		fmt.Fprint(flags.Output(), `
Examples:
  ios-files --output-dir exported-files
  ios-files --backup /path/to/backup --output-dir /path/to/export
  ios-files -b /path/to/backup -p /path/to/password.txt --camera-roll=false
`)
	}

	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if cfg.outputPath != "" {
		cfg.outputPath = filepath.Clean(cfg.outputPath)
	}
	if !cfg.extractCallHistory && !cfg.extractCameraRoll {
		return config{}, errors.New("at least one extraction target must be enabled")
	}

	return cfg, nil
}

// readPassword returns the backup password from passwordFile or stdin. An empty
// passwordFile requests an interactive prompt when stdin is a terminal.
func readPassword(passwordFile string, stdin io.Reader, stderr io.Writer) ([]byte, error) {
	if passwordFile != "" {
		if passwordFile == "-" {
			return readPasswordLine(stdin)
		}
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			return nil, err
		}
		return trimLineEnding(data), nil
	}

	inputFile, isFile := stdin.(*os.File)
	if isFile && term.IsTerminal(int(inputFile.Fd())) {
		fmt.Fprint(stderr, "Backup password: ")
		password, err := term.ReadPassword(int(inputFile.Fd()))
		fmt.Fprintln(stderr)
		return password, err
	}

	return readPasswordLine(stdin)
}

// readPasswordLine returns the first line from reader without its line ending.
func readPasswordLine(reader io.Reader) ([]byte, error) {
	buffered := bufio.NewReader(reader)
	line, err := buffered.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(line) == 0 && errors.Is(err, io.EOF) {
		return nil, errors.New("password input is empty")
	}
	return trimLineEnding(line), nil
}

// trimLineEnding returns value without one trailing Unix or Windows line ending.
func trimLineEnding(value []byte) []byte {
	value = []byte(strings.TrimSuffix(string(value), "\n"))
	value = []byte(strings.TrimSuffix(string(value), "\r"))
	return value
}
