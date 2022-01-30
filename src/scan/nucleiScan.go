package scan

import (
	. "getitle/src/nuclei/templates"
	"getitle/src/utils"
	"strings"
)

//tamplate =
func Nuclei(target string, result *utils.Result) {

	if RunOpt.Exploit == "auto" {
		execute_templates(result, result.Frameworks.GetTitles(), target)
	} else {
		execute_templates(result, strings.Split(RunOpt.Exploit, ","), target)
	}

}

func execute_templates(result *utils.Result, titles []string, target string) {
	var vulns []*utils.Vuln
	templates := choiceTemplates(titles)
	for _, template := range templates { // 遍历所有poc
		res, ok := template.Execute(target)
		if ok {
			for name, extract := range res.Extracts {
				result.AddExtract(utils.NewExtract(name, extract))
			}
			vulns = append(vulns, &utils.Vuln{template.Id, res.PayloadValues, res.DynamicValues, template.Info.Severity})
		}
	}

	result.AddVulns(vulns)
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
