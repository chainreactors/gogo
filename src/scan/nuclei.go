package scan

import (
	"getitle/src/utils"
)

//tamplate =
func Nuclei(url string, result *utils.Result) {
	var vulns []utils.Vuln
	if Exploit == "auto" {
		vulns = execute_templates(result.Framework, url)
	} else {
		vulns = execute_templates(Exploit, url)
	}
	if len(vulns) > 0 {
		result.Vulns = vulns
	}
}

func execute_templates(tag string, url string) []utils.Vuln {
	var vulns []utils.Vuln
	if templates, ok := utils.TemplateMap[tag]; ok {
		for _, template := range templates { // 遍历所有poc
			for _, request := range template.Requests { // 逐个执行requests,每个poc获取返回值后退出
				res, err := request.ExecuteRequestWithResults(url)
				if err != nil {
					println(err.Error())
				}
				if res != nil && res.Matched {
					vulns = append(vulns, utils.Vuln{template.Id, res.PayloadValues, res.DynamicValues})
					break
				}
			}
		}
	}
	return vulns
}
