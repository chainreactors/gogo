package fingers

import (
	"fmt"
	"strings"
)

const (
	None = iota
	ACTIVE
	ICO
	NOTFOUND
	GUESS
)

var FrameFromMap = map[int]string{
	ACTIVE:   "active",
	ICO:      "ico",
	NOTFOUND: "404",
	GUESS:    "guess",
}

type Framework struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	From    int    `json:"-"`
	FromStr string `json:"from"`
	IsFocus bool   `json:"is_focus"`
	Data    string `json:"-"`
}

func (f Framework) ToString() string {
	var s = f.Name
	if f.IsFocus {
		s = "focus:" + s
	}

	if f.Version != "" {
		s += ":" + strings.Replace(f.Version, ":", "_", -1)
	}
	if f.From != None {
		s += ":" + f.FromStr
	}
	return s
}

const (
	INFO int = iota + 1
	MEDIUM
	HIGH
	CRITICAL
)

var SeverityMap = map[string]int{
	"info":     INFO,
	"medium":   MEDIUM,
	"high":     HIGH,
	"critical": CRITICAL,
}

type Vuln struct {
	Name          string                 `json:"name"`
	Payload       map[string]interface{} `json:"payload,omitempty"`
	Detail        map[string]interface{} `json:"detail,omitempty"`
	Severity      string                 `json:"severity"`
	SeverityLevel int                    `json:"-"`
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
