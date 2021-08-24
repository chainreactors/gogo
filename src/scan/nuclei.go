package scan

import (
	"getitle/src/utils"
)

//tamplate =
func Nuclei(url string, result *utils.Result) {
	if template, ok := utils.TemplateMap[result.Framework]; ok {
		for _, request := range template.Requests {
			res, err := request.ExecuteRequestWithResults(url)
			if err != nil {
				println(err.Error())
			}
			if res != nil && res.Matched {
				result.Vuln = template.Id
				result.Vuln_Payload = utils.MaptoString(res.PayloadValues)
				result.Vuln_Detail = utils.MaptoString(res.DynamicValues)
				break
			}
		}
	}

}
