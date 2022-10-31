package pkg

import (
	"encoding/json"
	"fmt"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"strings"
)

var NoGuess bool

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
