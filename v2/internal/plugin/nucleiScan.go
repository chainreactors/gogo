package plugin

import (
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/gogo/v2/pkg/nuclei/templates"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"strings"
)

//tamplate =
func Nuclei(target string, result *Result) {
	if RunOpt.Exploit != "none" {
		if RunOpt.Exploit != "auto" {
			executeTemplates(result, strings.Split(RunOpt.Exploit, ","), target)
		} else {
			titles := result.Frameworks.GetNames()
			if result.IsHttp() {
				titles = append(titles, "http")
			}
			executeTemplates(result, titles, target)
		}
	}
}

func executeTemplates(result *Result, titles []string, target string) {
	var vulns []*parsers.Vuln
	ts := choiceTemplates(titles)
chainLoop: // 实现chain
	for {
		var chainsTemplates []*templates.Template
		for _, template := range ts { // 遍历所有poc
			logs.Log.Debugf("nuclei scan %s with %s", target, template.Id)
			res, ok := template.Execute(target)
			if ok {
				for name, extract := range res.Extracts {
					result.AddExtract(fingers.NewExtracted(name, extract))
				}
				vulns = append(vulns, &parsers.Vuln{Name: template.Id, Payload: res.PayloadValues, Detail: res.DynamicValues, Severity: template.Info.Severity})
				chainsTemplates = append(chainsTemplates, diffTemplates(ts, choiceTemplates(template.Chains))...)
			}
		}
		if chainsTemplates != nil {
			ts = chainsTemplates
			goto chainLoop
		} else {
			break
		}
	}
	result.AddVulns(vulns)
}

func choiceTemplates(titles []string) []*templates.Template {
	var ts []*templates.Template
	if len(titles) == 0 {
		return nil
	}
	if titles[0] == "all" {
		for _, tmpTemplates := range TemplateMap {
			ts = append(ts, tmpTemplates...)
		}
	} else {
		for _, t := range titles {
			if tmpTemplates, ok := TemplateMap[strings.ToLower(t)]; ok {
				ts = append(ts, tmpTemplates...)
			}
		}
	}
	return uniqueTemplates(ts)
}

func uniqueTemplates(ts []*templates.Template) []*templates.Template {
	tmpTemplates := make(map[*templates.Template]bool)
	for _, template := range ts {
		tmpTemplates[template] = true
	}
	uniquetemplates := make([]*templates.Template, len(tmpTemplates))
	i := 0
	for template, _ := range tmpTemplates {
		uniquetemplates[i] = template
		i++
	}
	return uniquetemplates
}

func diffTemplates(baseTemplates []*templates.Template, ts []*templates.Template) []*templates.Template {
	tmpTemplates := make(map[*templates.Template]bool)
	for _, template := range baseTemplates {
		tmpTemplates[template] = true
	}
	var uniqueTemplates []*templates.Template
	for _, t := range ts {
		if _, ok := tmpTemplates[t]; !ok {
			uniqueTemplates = append(uniqueTemplates, t)
		}
	}
	return uniqueTemplates
}
