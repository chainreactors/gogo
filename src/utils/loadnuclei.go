package utils

import (
	"encoding/json"
	"fmt"
	"getitle/src/nuclei/protocols"
	. "getitle/src/nuclei/templates"
	"io/ioutil"
	"os"
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

var TemplateMap map[string][]*Template

func LoadNuclei(filename string) map[string][]*Template {
	if filename == "" {
		return LoadTemplates(LoadConfig("nuclei"))
	} else {
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(0)
		}
		return LoadTemplates(content)
	}
}

func LoadTemplates(content []byte) map[string][]*Template {
	var templates []*Template
	var templatemap = make(map[string][]*Template)
	err := json.Unmarshal(content, &templates)
	if err != nil {
		fmt.Println("[-] " + err.Error())
		fmt.Println("[-] nuclei config load FAIL!")
		os.Exit(0)
	}
	for _, template := range templates {
		// 以指纹归类
		err = template.Compile(*ExecuterOptions)
		if err != nil {
			println(err.Error())
			os.Exit(0)
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
