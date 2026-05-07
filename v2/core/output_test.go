package core

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/parsers"
)

func TestOutputValuesDoesNotAppendTrailingDelimiter(t *testing.T) {
	result := &Result{
		GOGOResult: parsers.NewGOGOResult("127.0.0.1", "80"),
	}
	result.Protocol = "http"

	got := outputValues(result, "url", "\t")
	want := "http://127.0.0.1:80\n"
	if got != want {
		t.Fatalf("unexpected output: got %q want %q", got, want)
	}
}

func TestOutputResultsValuesUsesConfiguredDelimiter(t *testing.T) {
	first := parsers.NewGOGOResult("127.0.0.1", "80")
	first.Protocol = "http"
	second := parsers.NewGOGOResult("127.0.0.1", "443")
	second.Protocol = "https"

	results := parsers.GOGOResults{first, second}

	got := outputResultsValues(results, "ip,url", ",")
	want := "127.0.0.1,http://127.0.0.1:80\n127.0.0.1,https://127.0.0.1:443"
	if got != want {
		t.Fatalf("unexpected formatted values: got %q want %q", got, want)
	}
}

func TestOutputResultsValuesDeduplicatesIdenticalLines(t *testing.T) {
	first := parsers.NewGOGOResult("127.0.0.1", "80")
	second := parsers.NewGOGOResult("127.0.0.1", "443")

	results := parsers.GOGOResults{first, second}

	got := outputResultsValues(results, "ip", "\t")
	want := "127.0.0.1"
	if got != want {
		t.Fatalf("unexpected deduplicated values: got %q want %q", got, want)
	}
}

func TestDefaultConfigKeepsTabDelimiter(t *testing.T) {
	if DefaultConfig.OutputDelimiter != "\t" {
		t.Fatalf("unexpected default delimiter: %q", DefaultConfig.OutputDelimiter)
	}
}

func TestFormatOutputMultipleSegmentsDoesNotDuplicate(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "results.dat")
	outputFile := filepath.Join(dir, "targets.txt")

	content := `{"ip":"127.0.0.1","ports":"80","mod":"default","exploit":"none","json_type":"scan","version_level":0}
{"ip":"127.0.0.1","port":"80","protocol":"http","status":"200"}
["done"]
{"ip":"127.0.0.2","ports":"443","mod":"default","exploit":"none","json_type":"scan","version_level":0}
{"ip":"127.0.0.2","port":"443","protocol":"https","status":"200"}
["done"]
`
	if err := os.WriteFile(input, []byte(content), 0644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	FormatOutput(input, outputFile, "target", "", "\t", nil, false)

	gotBytes, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	want := "127.0.0.1:80\n127.0.0.2:443"
	if got := string(gotBytes); got != want {
		t.Fatalf("unexpected exported targets: got %q want %q", got, want)
	}
}
