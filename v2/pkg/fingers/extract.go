package fingers

import (
	"fmt"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"regexp"
)

type Extractors map[string]*regexp.Regexp

func (e Extractors) Extract(content string) (extracts []*Extracted) {
	if len(content) == 0 {
		return
	}

	for name, extract := range e {
		extractStr, ok := utils.CompiledAllMatch(extract, content)
		if ok && extractStr != nil {
			extracts = append(extracts, NewExtracted(name, extractStr))
		}
	}
	return extracts
}

func NewExtracted(name string, extractResult interface{}) *Extracted {
	var e = &Extracted{
		Name: name,
	}
	switch extractResult.(type) {
	case string:
		e.ExtractResult = append(e.ExtractResult, extractResult.(string))
	case []byte:
		e.ExtractResult = append(e.ExtractResult, string(extractResult.([]byte)))
	case []string:
		e.ExtractResult = append(e.ExtractResult, extractResult.([]string)...)
	}
	return e
}

type Extracted struct {
	Name          string   `json:"name"`
	ExtractResult []string `json:"extract_result"`
}

func (e *Extracted) ToString() string {
	if len(e.ExtractResult) == 1 {
		if len(e.ExtractResult[0]) > 30 {
			return fmt.Sprintf("%s:%s ... %d bytes", e.Name, utils.AsciiEncode(e.ExtractResult[0][:30]), len(e.ExtractResult[0]))
		}
		return fmt.Sprintf("%s:%s", e.Name, utils.AsciiEncode(e.ExtractResult[0]))
	} else {
		return fmt.Sprintf("%s:%d items", e.Name, len(e.ExtractResult))
	}
}
