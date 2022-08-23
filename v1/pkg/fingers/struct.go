package fingers

import (
	"fmt"
	"strings"
)

type Framework struct {
	Name    string `json:"ft"`
	Version string `json:"fv"`
	From    string `json:"ff"`
	IsGuess bool   `json:"fg"`
	IsFocus bool   `json:"ffc"`
	Data    string `json:"-"`
}

func (f Framework) ToString() string {
	var s = f.Name
	if f.IsGuess {
		s = "*" + s
	} else if f.IsFocus {
		s = "focus:" + s
	}

	if f.Version != "" {
		s += ":" + strings.Replace(f.Version, ":", "_", -1)
	}
	if f.From != "" {
		s += ":" + f.From
	}
	return s
}

const (
	Info int = iota + 1
	Medium
	High
	Critical
)

var serverityMap = map[string]int{
	"info":     Info,
	"medium":   Medium,
	"high":     High,
	"critical": Critical,
}

type Vuln struct {
	Name     string                 `json:"vn"`
	Payload  map[string]interface{} `json:"vp"`
	Detail   map[string]interface{} `json:"vd"`
	Severity string                 `json:"vs"`
}

func (v *Vuln) GetPayload() string {
	return mapToString(v.Payload)
}

func (v *Vuln) GetDetail() string {
	return mapToString(v.Detail)
}

func (v *Vuln) ToString() string {
	s := v.Name
	if payload := v.GetPayload(); payload != "" {
		s += fmt.Sprintf(" payloads:%s", payload)
	}
	if detail := v.GetDetail(); detail != "" {
		s += fmt.Sprintf(" payloads:%s", detail)
	}
	return s
}
