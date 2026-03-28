package core

import (
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

func TestDefaultConfigKeepsTabDelimiter(t *testing.T) {
	if DefaultConfig.OutputDelimiter != "\t" {
		t.Fatalf("unexpected default delimiter: %q", DefaultConfig.OutputDelimiter)
	}
}
