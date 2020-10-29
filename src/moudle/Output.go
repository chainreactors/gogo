package moudle

import (
	"encoding/json"
	"fmt"
)

func output(result map[string]string,outputformat string)  {
	switch outputformat {
	case "clean":
		cleanOutput(result)
	case "full":
		fullOutput(result)
	case "json":
		jsonOutput(result)
	}
}

func cleanOutput(result map[string]string)  {
	fmt.Printf("[+] %s://%s:%s [OPEN] %s \n",result["protocol"],result["ip"],result["port"],result["title"])
}

func fullOutput(result map[string]string)  {
	fmt.Printf("[+] %s://%s:%s [OPEN] [%s] [%s] [%s] [%s] \n",result["protocol"],result["ip"],result["port"],result["midware"],result["language"],result["framework"],result["title"])
}
func jsonOutput(result map[string]string)  {
	jsons, err := json.Marshal(result)
	if err == nil {
		println(string(jsons))
	}

}