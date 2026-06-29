package core

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunWithArgsRejectsInvalidFlag(t *testing.T) {
	var out bytes.Buffer

	err := RunWithArgs(context.Background(), []string{"--definitely-not-a-flag"}, RunOptions{
		Output: &out,
	})
	if err == nil {
		t.Fatal("expected invalid flag to return an error")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunWithArgsHelp(t *testing.T) {
	var out bytes.Buffer

	if err := RunWithArgs(context.Background(), []string{"--help"}, RunOptions{
		Output: &out,
	}); err != nil {
		t.Fatal(err)
	}

	if got := out.String(); !strings.Contains(got, "WIKI: https://chainreactors.github.io/wiki/gogo/") ||
		!strings.Contains(got, "gogo -i 1.1.1.1/24 -p top2,win,db -ev") {
		t.Fatalf("unexpected help output: %q", got)
	}
}
