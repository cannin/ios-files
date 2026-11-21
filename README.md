# ios-files

`ios-files` is a Go command-line tool that extracts camera-roll files and call
history from local Finder or iTunes iOS backups. It supports encrypted and
unencrypted backups and processes both locally.

## Quick start

Prebuilt binaries are available for Linux, macOS, and Windows on AMD64 and
ARM64. [GitHub Releases](https://github.com/cannin/ios-files/releases)

Install Go 1.24 or newer and Make, then run these commands from the repository
root:

```sh
make -C go current
./go/dist/ios-files --output-dir output
```

This exports the camera roll from the newest backup under
`~/Library/Application Support/MobileSync/Backup`. The CLI prompts for a password
in an interactive terminal only when the selected backup is encrypted.

## Usage

Select a backup directory containing `Manifest.plist` and `Manifest.db`, or
provide a parent directory to select its newest backup.

```sh
./go/dist/ios-files --backup /path/to/backup --output-dir /path/to/export
```

Add `--call-history` to export `call_history.sqlite` alongside the camera roll.
Use `--call-history --camera-roll=false` to export only call history.

For an encrypted backup, you can supply a password from a protected file with
`--password-file /path/to/password.txt`. Use `--password-file -` to read it from
standard input. Unencrypted backups skip password input. Run
`./go/dist/ios-files -h` to see all options.

## Configuration

| Option | Purpose | Default |
| --- | --- | --- |
| `-b`, `--backup` | Device backup directory or parent backup root | `~/Library/Application Support/MobileSync/Backup` |
| `-o`, `--output`, `--output-dir` | Export directory | `output` |
| `-p`, `--password-file` | Password file or `-` for standard input | Interactive prompt for encrypted backups |
| `-c`, `--call-history` | Export call history | `false` |
| `-r`, `--camera-roll` | Export camera-roll files | `true` |
| `-d`, `--debug` | Write a local JSONL diagnostic log | `true` |

## Exports and diagnostics

Each camera-roll run checks existing files against their recorded sizes. Missing
files are exported, and wrong-sized files are replaced after the replacement is
validated. Camera-roll files are flattened into `camera_roll/`. Duplicate names
receive `_2`, `_3`, and later suffixes before the extension. The tool restores
modification times and also restores creation times on macOS where supported by
the destination filesystem.

The command reports progress and elapsed time. Diagnostic logs in the current
directory can include personal file paths and error messages. Use
`--debug=false` to disable them, and redact logs before sharing excerpts.

Encrypted-backup tests use synthetic data. While opening an encrypted backup,
the tool stores a decrypted copy of `Manifest.db` in a restricted temporary
file. Normal shutdown removes the file. An interruption can leave it in the
system temporary directory.

## Release builds

```sh
make -C go all
```

This runs the tests and rebuilds `go/dist/` with Linux, macOS, and Windows binaries
for AMD64 and ARM64, plus a native build for the current system.

Pushing a tag such as `v0.1.0` runs the release workflow and publishes the six
platform binaries on GitHub.

## Acknowledgments

Inspired by [jsharkey13/iphone_backup_decrypt](https://github.com/jsharkey13/iphone_backup_decrypt).
