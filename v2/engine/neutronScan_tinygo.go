//go:build tinygo
// +build tinygo

package engine

import (
	"strings"

	"github.com/chainreactors/fingers/common"
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/templates"
	"github.com/chainreactors/utils/parsers"
)

func NeutronScan(opt *RunnerOption, target string, result *Result) {
	if opt.Exploit != "none" {
		if opt.Exploit != "auto" {
			executeTemplates(result, strings.Split(opt.Exploit, ","), target)
		} else {
			pocs := result.Frameworks.GetNames()
			if result.IsHttp {
				pocs = append(pocs, "http")
			}
			executeTemplates(result, pocs, target)
		}
	}
}

func executeTemplates(result *Result, pocs []string, target string) {
	var vulns []*common.Vuln

	index := make(map[string]*templates.Template)
	startIDs := choiceTemplateIDs(pocs, index)

	ChainExec.Execute(startIDs, func(id string, vars map[string]interface{}) *templates.ChainResult {
		tmpl, ok := index[id]
		if !ok {
			return nil
		}
		logs.Log.Debugf("neutron scan %s with %s", target, id)
		res, err := tmpl.Execute(target, nil)
		if err != nil || res == nil {
			logs.Log.Debugf("neutron scan %s with %s error: %v", target, id, err)
			return nil
		}
		for name, extract := range res.Extracts {
			result.AddExtract(&parsers.Extracted{Name: name, ExtractResult: extract})
		}
		vulns = append(vulns, &common.Vuln{
			Name:          tmpl.Id,
			Payload:       res.PayloadValues,
			Detail:        res.DynamicValues,
			SeverityLevel: common.GetSeverityLevel(tmpl.Info.Severity),
			Tags:          strings.Split(tmpl.Info.Tags, ","),
		})
		return &templates.ChainResult{}
	})

	result.AddVulns(vulns)
}

// choiceTemplateIDs selects templates by name/tag/finger, populates index, and returns unique IDs.
func choiceTemplateIDs(titles []string, index map[string]*templates.Template) []string {
	if len(titles) == 0 {
		return nil
	}
	var sources [][]*templates.Template
	if titles[0] == "all" {
		for _, tmpls := range TemplateMap {
			sources = append(sources, tmpls)
		}
	} else {
		for _, t := range titles {
			if tmpls, ok := TemplateMap[strings.ToLower(t)]; ok {
				sources = append(sources, tmpls)
			}
		}
	}
	var ids []string
	for _, tmpls := range sources {
		for _, tmpl := range tmpls {
			if _, dup := index[tmpl.Id]; dup {
				continue
			}
			index[tmpl.Id] = tmpl
			ids = append(ids, tmpl.Id)
		}
	}
	return ids
}
