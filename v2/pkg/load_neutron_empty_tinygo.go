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

var (
	TemplateMap map[string][]*templates.Template
	ChainExec   *templates.ChainExecutor
)

func ParserCmdPayload([]string) map[string]interface{} {
	return make(map[string]interface{})
}

func LoadNeutron(string) (map[string][]*templates.Template, error) {
	ChainExec = templates.NewChainExecutor(templates.ChainConfig{})
	return make(map[string][]*templates.Template), nil
}

func LoadTemplates([]byte) (map[string][]*templates.Template, error) {
	ChainExec = templates.NewChainExecutor(templates.ChainConfig{})
	return make(map[string][]*templates.Template), nil
}
