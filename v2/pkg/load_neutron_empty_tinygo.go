//go:build tinygo && emptytemplates
// +build tinygo,emptytemplates

package pkg

import (
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
)

var ExecuterOptions *protocols.ExecuterOptions = &protocols.ExecuterOptions{
	Options: &protocols.Options{
		Timeout: 5,
	},
}

var TemplateMap map[string][]*templates.Template

func ParserCmdPayload([]string) map[string]interface{} {
	return make(map[string]interface{})
}

func LoadNeutron(string) map[string][]*templates.Template {
	return make(map[string][]*templates.Template)
}

func LoadTemplates([]byte) map[string][]*templates.Template {
	return make(map[string][]*templates.Template)
}
