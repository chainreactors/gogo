//go:build !tinygo
// +build !tinygo

package pkg

import (
	"fmt"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils/encode"
	"github.com/chainreactors/utils/fileutils"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"strings"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
)

var ExecuterOptions *protocols.ExecuterOptions = &protocols.ExecuterOptions{
	Options: &protocols.Options{
		Timeout: 5,
	},
}

func ParserCmdPayload(payloads []string) map[string]interface{} {
	var vars = make(map[string]interface{})
	for _, payload := range payloads {
		if i := strings.Index(payload, "="); i != -1 {
			//content := files.LoadCommonArg(payload[i+1:])
			var content []byte
			if f, err := fileutils.Open(payload[i+1:]); err != nil {
				content = []byte(payload[i+1:])
			} else {
				content = fileutils.DecryptFile(f, nil)
			}
			vars[payload[:i]] = CleanSpiltCFLR(string(content))
		} else {
			fmt.Println("[warn] incorrect format, skip " + payload)
		}
	}

	return vars
}

var TemplateMap map[string][]*templates.Template

func LoadNeutron(filename string) (map[string][]*templates.Template, error) {
	var content []byte
	if filename == "" {
		return LoadTemplates(LoadConfig("neutron"))
	} else {
		if fileutils.IsExist(filename) {
			var err error
			content, err = ioutil.ReadFile(filename)
			if err != nil {
				return nil, err
			}
		} else {
			content = encode.Base64Decode(filename)
		}
		return LoadTemplates(content)
	}
}

func LoadTemplates(content []byte) (map[string][]*templates.Template, error) {
	if len(content) == 0 {
		return make(map[string][]*templates.Template), nil
	}

	var t []*templates.Template

	var templatemap = make(map[string][]*templates.Template)
	err := yaml.Unmarshal(content, &t)
	if err != nil {
		return nil, fmt.Errorf("neutron config load FAIL!, %s", err.Error())
	}
	for _, template := range t {
		err = template.Compile(ExecuterOptions)
		if err != nil {
			continue
		}

		for _, finger := range template.Fingers {
			templatemap[strings.ToLower(finger)] = append(templatemap[strings.ToLower(finger)], template)
		}

		if template.Id != "" {
			templatemap[strings.ToLower(template.Id)] = append(templatemap[strings.ToLower(template.Id)], template)
		}

		// 以tag归类
		for _, tag := range template.GetTags() {
			tag := strings.ToLower(tag)
			templatemap[tag] = append(templatemap[tag], template)
		}

		// add zombie-finger map
		if template.Info.Zombie != "" {
			for _, tag := range template.GetTags() {
				parsers.ZombieMap[strings.ToLower(tag)] = template.Info.Zombie
			}
			for _, finger := range template.Fingers {
				parsers.ZombieMap[finger] = template.Info.Zombie
			}
		}
	}
	parsers.RegisterZombieServiceAlias()
	return templatemap, nil
}
