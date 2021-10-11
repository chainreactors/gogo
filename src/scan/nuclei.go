package scan

import (
	. "getitle/src/nuclei/templates"
	"getitle/src/utils"
	"strings"
)

//tamplate =
func Nuclei(url string, result *utils.Result) {
	var vulns []utils.Vuln

	if Exploit == "auto" {
		vulns = execute_templates(result.Frameworks.GetTitles(), url)
	} else {
		vulns = execute_templates([]string{Exploit}, url)
	}
	if len(vulns) > 0 {
		result.AddVulns(vulns)
	}
}

func execute_templates(titles []string, url string) []utils.Vuln {
	var vulns []utils.Vuln
	templates := choiceTemplates(titles)
	for _, template := range templates { // 遍历所有poc
		for _, request := range template.RequestsHttp { // 逐个执行requests,每个poc获取返回值后退出
			res, _ := request.ExecuteRequestWithResults(url)
			if res != nil && res.Matched {
				vulns = append(vulns, utils.Vuln{template.Id, res.PayloadValues, res.DynamicValues})
				break
			}
		}
	}

	return vulns
}

func choiceTemplates(titles []string) []*Template {
	var templates []*Template
	if titles[0] == "all" {
		for _, tmp_templates := range utils.TemplateMap {
			templates = append(templates, tmp_templates...)
		}

	} else {
		for _, t := range titles {
			if tmp_templates, ok := utils.TemplateMap[strings.ToLower(t)]; ok {
				templates = append(templates, tmp_templates...)
			}
		}
	}
	return uniqueTemplates(templates)
}

func uniqueTemplates(templates []*Template) []*Template {
	tmp_templates := make(map[*Template]bool)
	for _, template := range templates {
		tmp_templates[template] = true
	}
	uniquetemplates := make([]*Template, len(tmp_templates))
	i := 0
	for template, _ := range tmp_templates {
		uniquetemplates[i] = template
		i++
	}
	return uniquetemplates
}
