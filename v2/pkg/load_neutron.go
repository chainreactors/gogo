package pkg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/chainreactors/files"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates_gogo"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils/iutils"
)

var ExecuterOptions *protocols.ExecuterOptions

func ParserCmdPayload(payloads []string) *protocols.ExecuterOptions {
	var options = &protocols.ExecuterOptions{
		Options: &protocols.Options{
			VarsPayload: map[string]interface{}{},
		},
	}

	var vars = make(map[string]interface{})
	for _, payload := range payloads {
		if i := strings.Index(payload, "="); i != -1 {
			//content := files.LoadCommonArg(payload[i+1:])
			var content []byte
			if f, err := files.Open(payload[i+1:]); err != nil {
				content = []byte(payload[i+1:])
			} else {
				content = files.DecryptFile(f, nil)
			}
			vars[payload[:i]] = CleanSpiltCFLR(string(content))
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

func LoadNeutron(filename string) map[string][]*templates.Template {
	var content []byte
	if filename == "" {
		return LoadTemplates(LoadConfig("nuclei"))
	} else {
		if IsExist(filename) {
			var err error
			content, err = ioutil.ReadFile(filename)
			if err != nil {
				iutils.Fatal(err.Error())
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
		iutils.Fatal("neutron config load FAIL!, " + err.Error())
	}
	for _, template := range t {
		// 以指纹归类
		err = template.Compile(ExecuterOptions)
		if err != nil {
			iutils.Fatal("" + err.Error())
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
