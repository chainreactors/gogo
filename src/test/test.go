package main

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

//func main() {
//	var (
//		negotiateProtocolRequest = Unzip("H4sIAAAAAAAA/2JgYGj9H+zrVMTAwMAgEXyAAQX8/8fA4MDAkMTAFOCs4OcaEu4f5K0QEOTvHuToq2CoZ8DA5OPo5+voB2aGZ+al5JcXK6TlFymE5xdlpxfllxYUKxjrGSYyMPn4GuoZRRgYGMG0GOkZMjD5hSj4+CoY6BkaMQAAAAD//wEAAP//1eOKXIkAAAA=")
//		sessionSetupRequest      = Unzip("H4sIAAAAAAAA/2JgYOj4H+zrVMzAwMAgwX6AAQX8/8fA4MDA+5+hg4FFkAsqyAilrzAwMHhDmOEMmQx5DCkM+QzlDMUMCgxGDAZgCGIZMlgymOJVY8qgx2DAwMAAAAAA//8BAAD//5V7xReMAAAA")
//		treeConnectRequest       = Unzip("H4sIAAAAAAAA/1TFsQkCMQAAwBMEM4IDWAsJRGOlaGUhCLYpsoT7/WSf59P9NYfWf5/nH46HyUafhYd91wQ7maqKbpKz6KKMr/I4Kaq3r5cT7isLAAAA//8BAAD///L5u6lkAAAA")
//		transNamedPipeRequest    = Unzip("H4sIAAAAAAAA/2JgYPD6H+zrpMrAwMAgwajBgAw4+hYzcgTNEACx/////x9ZzguMmRiUGRgY2BliAjwDXGMYAAAAAP//AQAA//+OaounTgAAAA==")
//	)
//	println(Encode(negotiateProtocolRequest))
//	//println(s)
//	println(Encode(sessionSetupRequest))
//	println(Encode(treeConnectRequest))
//	println(Encode(transNamedPipeRequest))
//}
