package scan

import (
	. "getitle/src/fingers"
	. "getitle/src/nuclei/templates"
	. "getitle/src/pkg"
	"strings"
)

//tamplate =
func Nuclei(target string, result *Result) {

	if RunOpt.Exploit == "auto" {
		execute_templates(result, result.Frameworks.GetTitles(), target)
	} else {
		execute_templates(result, strings.Split(RunOpt.Exploit, ","), target)
	}

}

func execute_templates(result *Result, titles []string, target string) {
	var vulns []*Vuln
	templates := choiceTemplates(titles)
chainLoop:
	for {
		var chainsTemplates []*Template
		for _, template := range templates { // 遍历所有poc
			Log.Debugf("nuclei scan %s with %s", target, template.Id)
			res, ok := template.Execute(target)
			if ok {
				for name, extract := range res.Extracts {
					result.AddExtract(NewExtract(name, extract))
				}
				vulns = append(vulns, &Vuln{template.Id, res.PayloadValues, res.DynamicValues, template.Info.Severity})
				chainsTemplates = append(chainsTemplates, diffTemplates(templates, choiceTemplates(template.Chains))...)
			}
		}
		if chainsTemplates != nil {
			templates = chainsTemplates
			goto chainLoop
		} else {
			break
		}
	}
	result.AddVulns(vulns)
}

func choiceTemplates(titles []string) []*Template {
	var templates []*Template
	if len(titles) == 0 {
		return nil
	}
	if titles[0] == "all" {
		for _, tmpTemplates := range TemplateMap {
			templates = append(templates, tmpTemplates...)
		}
	} else {
		for _, t := range titles {
			if tmpTemplates, ok := TemplateMap[strings.ToLower(t)]; ok {
				println(t, ok)
				templates = append(templates, tmpTemplates...)
			}
		}
	}
	return uniqueTemplates(templates)
}

func uniqueTemplates(templates []*Template) []*Template {
	tmpTemplates := make(map[*Template]bool)
	for _, template := range templates {
		tmpTemplates[template] = true
	}
	uniquetemplates := make([]*Template, len(tmpTemplates))
	i := 0
	for template, _ := range tmpTemplates {
		uniquetemplates[i] = template
		i++
	}
	return uniquetemplates
}

func diffTemplates(baseTemplates []*Template, templates []*Template) []*Template {
	tmpTemplates := make(map[*Template]bool)
	for _, template := range baseTemplates {
		tmpTemplates[template] = true
	}
	var uniqueTemplates []*Template
	for _, t := range templates {
		if _, ok := tmpTemplates[t]; !ok {
			uniqueTemplates = append(uniqueTemplates, t)
		}
	}
	println(len(uniqueTemplates))
	return uniqueTemplates
}
