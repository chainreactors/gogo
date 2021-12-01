package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
)

func LoadResult(filename string) (*ResultsData, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	content = bytes.TrimSpace(content)
	// 自动修复未完成任务的json
	laststr := string(content[len(content)-2:])
	if laststr != "]}" {
		content = append(content, "]}"...)
		fmt.Println("[*] Task has not been completed,auto fix json")
		fmt.Println("[*] Task has not been completed,auto fix json")
		fmt.Println("[*] Task has not been completed,auto fix json")
	}

	var resultsdata *ResultsData
	err = json.Unmarshal(content, &resultsdata)
	if err != nil {
		fmt.Println("[-] json error, " + err.Error())
		return nil, err
	}

	return resultsdata, err
}
