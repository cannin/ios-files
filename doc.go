/*
Ios-files extracts call history and camera-roll files from Apple device backups.

It accepts either a specific device backup directory or a parent directory
containing backups. When given a parent directory, it selects the newest valid
backup. For encrypted backups, it reads the password interactively, from a file,
or from standard input.
*/
package main
