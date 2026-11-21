package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestProgressDisplayIncludesPercentageAndCounts(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	display := newProgressDisplay(&output)
	display.Update(0, 4)
	display.Update(2, 4)
	display.Update(4, 4)
	display.Finish()

	for _, expected := range []string{"0.00% (0/4)", "50.00% (2/4)", "100.00% (4/4)"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("progress output lacks %q: %q", expected, output.String())
		}
	}
}

func TestProgressDisplayHandlesEmptyExtraction(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	newProgressDisplay(&output).Update(0, 0)
	if !strings.Contains(output.String(), "100.00% (0/0)") {
		t.Fatalf("empty progress output = %q", output.String())
	}
}
