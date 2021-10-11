package templates

import (
	"getitle/src/nuclei/http"
	"strings"
)

type Template struct {
	Id     string `json:"id"`
	Finger string `json:"finger"`
	Info   struct {
		Name      string `json:"name"`
		Author    string `json:"author"`
		Severity  string `json:"severity"`
		Reference string `json:"reference"`
		Vendor    string `json:"vendor"`
		Tags      string `json:"tags"`
	} `json:"info"`
	RequestsHttp []http.Request `json:"requests"`
	//RequestsTCP []tcp.Request `json:"network"`
}

func (t *Template) GetTags() []string {
	if t.Info.Tags != "" {
		return strings.Split(t.Info.Tags, ",")
	}
	return []string{}
}
