package fingers

import (
	"fmt"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"regexp"
)

var PresetExtracts = map[string]*regexp.Regexp{
	"url":      regexp.MustCompile(`(http|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:\/~\+#]*[\w\-\@?^=%&\/~\+#])?`),
	"ip":       regexp.MustCompile("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}"),
	"mail":     regexp.MustCompile("([A-Za-z0-9_\\-\\.\u4e00-\u9fa5])+\\@([A-Za-z0-9_\\-\\.])+\\.([A-Za-z]{2,8})"),
	"idcard":   regexp.MustCompile("(\\d{15}$)|(^\\d{17}([0-9]|[xX]))"),
	"phone":    regexp.MustCompile("(\\+?0?86\\-?)?1[3-9]\\d{9}"),
	"header":   regexp.MustCompile("(?U)^HTTP(?:.|\n)*[\r\n]{4}"),
	"body":     regexp.MustCompile("[\\r\\n]{4}[\\w\\W]*"),
	"cookie":   regexp.MustCompile("(?i)Set-Cookie.*"),
	"response": regexp.MustCompile("(?s).*"),
}

type Extractors map[string]*regexp.Regexp

func (e Extractors) Extract(content string) (extracts []*Extracted) {
	if len(content) == 0 {
		return
	}

	for name, extract := range e {
		extractStr, ok := compiledAllMatch(extract, content)
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
