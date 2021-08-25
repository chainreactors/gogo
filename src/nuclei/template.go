package nuclei

import "strings"

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
	Requests []Request `json:"requests"`
}

func (t *Template) GetTags() []string {
	if t.Info.Tags != "" {
		return strings.Split(t.Info.Tags, ",")
	}
	return []string{}
}
