package pkg

import (
	"encoding/json"
	"fmt"
	protocols2 "getitle/v1/pkg/nuclei/protocols"
	. "getitle/v1/pkg/nuclei/templates"
	"io/ioutil"
	"strings"
)

var ExecuterOptions *protocols2.ExecuterOptions

func ParserCmdPayload(payloads []string) *protocols2.ExecuterOptions {
	var options = &protocols2.ExecuterOptions{
		Options: &protocols2.Options{
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

var TemplateMap map[string][]*Template

func LoadNuclei(filename string) map[string][]*Template {
	if filename == "" {
		return LoadTemplates(LoadConfig("nuclei"))
	} else {
		var content []byte
		if IsExist(filename) {
			var err error
			content, err = ioutil.ReadFile(filename)
			if err != nil {
				Fatal(err.Error())
			}
		} else {
			content = Base64Decode(filename)
		}
		return LoadTemplates(content)
	}
}

func LoadTemplates(content []byte) map[string][]*Template {
	var templates []*Template
	var templatemap = make(map[string][]*Template)
	err := json.Unmarshal(content, &templates)
	if err != nil {
		Fatal("nuclei config load FAIL!, " + err.Error())
	}
	for _, template := range templates {
		// 以指纹归类
		err = template.Compile(*ExecuterOptions)
		if err != nil {
			Fatal("" + err.Error())
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
