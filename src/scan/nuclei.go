package scan

import (
	"getitle/src/nuclei"
	"getitle/src/utils"
	"strings"
)

//tamplate =
func Nuclei(url string, result *utils.Result) {
	var vulns []utils.Vuln

	// 设置延迟
	opt := nuclei.Defaultoption
	opt.Timeout = Delay
	if result.IsHttps() {
		opt.Timeout += HttpsDelay
	}

	if Exploit == "auto" {
		vulns = execute_templates(result.Frameworks.GetTitles(), url, opt)
	} else {
		vulns = execute_templates([]string{Exploit}, url, opt)
	}
	if len(vulns) > 0 {
		result.AddVulns(vulns)
	}
}

func execute_templates(titles []string, url string, opt nuclei.Options) []utils.Vuln {
	var vulns []utils.Vuln
	templates := choiceTemplates(titles)
	for _, template := range templates { // 遍历所有poc
		for _, request := range template.Requests { // 逐个执行requests,每个poc获取返回值后退出
			res, _ := request.ExecuteRequestWithResults(url, opt)
			if res != nil && res.Matched {
				vulns = append(vulns, utils.Vuln{template.Id, res.PayloadValues, res.DynamicValues})
				break
			}
		}
	}

	return vulns
}

func choiceTemplates(titles []string) []*nuclei.Template {
	var templates []*nuclei.Template
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

func uniqueTemplates(templates []*nuclei.Template) []*nuclei.Template {
	tmp_templates := make(map[*nuclei.Template]bool)
	for _, template := range templates {
		tmp_templates[template] = true
	}
	uniquetemplates := make([]*nuclei.Template, len(tmp_templates))
	i := 0
	for template, _ := range tmp_templates {
		uniquetemplates[i] = template
		i++
	}
	return uniquetemplates
}
