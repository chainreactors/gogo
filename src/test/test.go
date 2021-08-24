package test

import (
	"encoding/json"
	"fmt"
	"getitle/src/nuclei"
	"getitle/src/utils"
	"os"
)

func main() {
	var templaces []nuclei.Template
	err := json.Unmarshal([]byte(utils.LoadConfig("nuclei")), &templaces)
	if err != nil {
		os.Exit(0)
	}
	req := templaces[0].Requests[0]
	url := "https://183.62.11.227:4430"
	res, err := req.ExecuteRequestWithResults(url)
	if res != nil && res.Matched {
		fmt.Printf("[+] find vuln %s:%s", templaces[0].Id, url)
	}
}
