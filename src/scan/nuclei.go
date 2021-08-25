package scan

import (
	"getitle/src/nuclei"
	"getitle/src/utils"
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
		vulns = execute_templates(result.Framework, url, opt)
	} else {
		vulns = execute_templates(Exploit, url, opt)
	}
	if len(vulns) > 0 {
		result.Vulns = vulns
	}
}

func execute_templates(tag string, url string, opt nuclei.Options) []utils.Vuln {
	var vulns []utils.Vuln
	if templates, ok := utils.TemplateMap[tag]; ok {
		for _, template := range templates { // 遍历所有poc
			for _, request := range template.Requests { // 逐个执行requests,每个poc获取返回值后退出
				res, err := request.ExecuteRequestWithResults(url, opt)
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
