package main

import (
	"encoding/hex"
	"getitle/src/structutils"
)

//import (
//	"encoding/json"
//	"fmt"
//	"getitle/src/nuclei/templates"
//	"getitle/src/utils"
//	"os"
//)
//
//func main() {
//	var templaces []templates.Template
//	err := json.Unmarshal([]byte(utils.LoadConfig("nuclei")), &templaces)
//	if err != nil {
//		os.Exit(0)
//	}
//	req := templaces[0].RequestsHTTP[0]
//	url := "https://183.62.11.227:4430"
//	res, err := req.ExecuteRequestWithResults(url)
//	if res != nil && res.Matched {
//		fmt.Printf("[+] find vuln %s:%s", templaces[0].Id, url)
//	}
//}

func main() {
	var (
		trans2SessionSetupRequest, _ = hex.DecodeString("0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")
	)
	println(structutils.Encode(trans2SessionSetupRequest))
}
