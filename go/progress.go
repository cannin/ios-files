package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// progressBarWidth is the number of characters inside the progress bar.
const progressBarWidth = 30

// A progressDisplay renders extraction progress to a terminal or log stream.
type progressDisplay struct {
	writer              io.Writer
	interactive         bool
	lastLineLength      int
	lastReportedPercent int
	lineOpen            bool
}

// newProgressDisplay returns a progress display configured for writer.
func newProgressDisplay(writer io.Writer) *progressDisplay {
	display := &progressDisplay{writer: writer, lastReportedPercent: -1}
	if outputFile, ok := writer.(*os.File); ok {
		display.interactive = term.IsTerminal(int(outputFile.Fd()))
	}
	return display
}

// Update renders the current extraction percentage and processed file count.
func (display *progressDisplay) Update(processed, expected int) {
	if processed < 0 {
		processed = 0
	}
	if expected < 0 {
		expected = 0
	}
	if expected > 0 && processed > expected {
		processed = expected
	}

	percentage := 100.0
	if expected > 0 {
		percentage = float64(processed) * 100 / float64(expected)
	}
	filledWidth := progressBarWidth
	if expected > 0 {
		filledWidth = processed * progressBarWidth / expected
	}
	bar := strings.Repeat("#", filledWidth) + strings.Repeat("-", progressBarWidth-filledWidth)
	line := fmt.Sprintf("[%s] %6.2f%% (%d/%d)", bar, percentage, processed, expected)
	complete := processed >= expected

	if display.interactive {
		padding := ""
		if display.lastLineLength > len(line) {
			padding = strings.Repeat(" ", display.lastLineLength-len(line))
		}
		fmt.Fprintf(display.writer, "\r%s%s", line, padding)
		display.lastLineLength = len(line)
		display.lineOpen = true
		if complete {
			fmt.Fprintln(display.writer)
			display.lineOpen = false
		}
		return
	}

	wholePercent := int(percentage)
	if processed != 0 && !complete && wholePercent == display.lastReportedPercent {
		return
	}
	fmt.Fprintln(display.writer, line)
	display.lastReportedPercent = wholePercent
}

// Finish terminates an incomplete interactive progress line.
func (display *progressDisplay) Finish() {
	if display.interactive && display.lineOpen {
		fmt.Fprintln(display.writer)
		display.lineOpen = false
	}
}
