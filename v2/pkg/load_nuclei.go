package pkg

import (
	"encoding/json"
	"fmt"
	"github.com/chainreactors/gogo/v2/pkg/nuclei/protocols"
	"github.com/chainreactors/gogo/v2/pkg/nuclei/templates"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/parsers"
	"io/ioutil"
	"strings"
)

var ExecuterOptions *protocols.ExecuterOptions

func ParserCmdPayload(payloads []string) *protocols.ExecuterOptions {
	var options = &protocols.ExecuterOptions{
		Options: &protocols.Options{
			VarsPayload: map[string]interface{}{},
		},
	}

	var vars = make(map[string][]interface{})
	for _, payload := range payloads {
		if i := strings.Index(payload, ":"); i != -1 {
			vars[payload[:i]] = append(vars[payload[:i]], payload[i+1:])
		} else {
			fmt.Println("[warn] incorrect format, skip " + payload)
		}
	}
	for k, v := range vars {
		options.Options.VarsPayload[k] = v
	}
	return options
}

var TemplateMap map[string][]*templates.Template

func LoadNuclei(filename string) map[string][]*templates.Template {
	if filename == "" {
		return LoadTemplates(LoadConfig("nuclei"))
	} else {
		var content []byte
		if IsExist(filename) {
			var err error
			content, err = ioutil.ReadFile(filename)
			if err != nil {
				utils.Fatal(err.Error())
			}
		} else {
			content = parsers.Base64Decode(filename)
		}
		return LoadTemplates(content)
	}
}

func LoadTemplates(content []byte) map[string][]*templates.Template {
	var t []*templates.Template

	var templatemap = make(map[string][]*templates.Template)
	err := json.Unmarshal(content, &t)
	if err != nil {
		utils.Fatal("nuclei config load FAIL!, " + err.Error())
	}
	for _, template := range t {
		// 以指纹归类
		err = template.Compile(*ExecuterOptions)
		if err != nil {
			utils.Fatal("" + err.Error())
		}

		for _, finger := range template.Fingers {
			templatemap[strings.ToLower(finger)] = append(templatemap[strings.ToLower(finger)], template)
		}

		if template.Id != "" {
			templatemap[strings.ToLower(template.Id)] = append(templatemap[strings.ToLower(template.Id)], template)
		}

		// 以tag归类
		for _, tag := range template.GetTags() {
			templatemap[strings.ToLower(tag)] = append(templatemap[strings.ToLower(tag)], template)
		}
	}
	return templatemap
}
