package scan

import (
	"getitle/src/utils"
)

//tamplate =
func Nuclei(url string, result *utils.Result) {
	if templates, ok := utils.TemplateMap[result.Framework]; ok {
		for _, template := range templates { // 遍历所有poc
			for _, request := range template.Requests { // 逐个执行requests,每个poc获取返回值后退出
				res, err := request.ExecuteRequestWithResults(url)
				if err != nil {
					println(err.Error())
				}
				if res != nil && res.Matched {
					vuln := utils.Vuln{template.Id, res.PayloadValues, res.DynamicValues}
					result.AddVuln(vuln)
					break
				}
			}
		}
	}
}
