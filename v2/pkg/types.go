package pkg

import (
	"encoding/json"
	"fmt"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"strings"
)

var NoGuess bool

type Vulns []*fingers.Vuln

func (vs Vulns) ToString() string {
	var s string

	for _, vuln := range vs {
		s += fmt.Sprintf("[ %s: %s ] ", vuln.Severity, vuln.ToString())
	}
	return s
}

type Frameworks []*fingers.Framework

func (fs Frameworks) ToString() string {
	frameworkStrs := make([]string, len(fs))
	for i, f := range fs {
		if f.From == fingers.GUESS {
			continue
		}
		frameworkStrs[i] = f.ToString()
	}
	return strings.Join(frameworkStrs, "||")
}

func (fs Frameworks) GetNames() []string {
	var titles []string
	for _, f := range fs {
		if f.From != fingers.GUESS {
			titles = append(titles, f.Name)
		}
	}
	return titles
}

func (fs Frameworks) IsFocus() bool {
	for _, f := range fs {
		if f.IsFocus {
			return true
		}
	}
	return false
}

type Extracts struct {
	Target       string               `json:"target"`
	MatchedNames []string             `json:"-"`
	Extractors   []*fingers.Extracted `json:"extracts"`
}

func (es *Extracts) ToResult() string {
	s, err := json.Marshal(es)
	if err != nil {
		return err.Error()
	}
	return string(s)
}

func (es *Extracts) ToString() string {
	if es == nil {
		return ""
	}
	var s strings.Builder
	for _, e := range es.Extractors {
		s.WriteString(fmt.Sprintf("[ Extract: %s ] ", e.ToString()))
	}
	return s.String()
}
