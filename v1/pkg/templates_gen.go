//go:build ignore
// +build ignore

package main

import (
	"encoding/json"
	"fmt"
	. "getitle/v1/pkg"
	"io"
	"os"
	"path/filepath"
	"sigs.k8s.io/yaml"
)

func loadYamlFile2JsonString(filename string) string {
	var err error
	file, err := os.Open("v1/config/" + filename)
	if err != nil {
		panic(err.Error())
	}

	bs, _ := io.ReadAll(file)
	jsonstr, err := yaml.YAMLToJSON(bs)
	if err != nil {
		panic(filename + err.Error())
	}

	return Encode(jsonstr)
}

func visit(files *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			panic(err)
		}
		if !info.IsDir() {
			*files = append(*files, path)
		}
		return nil
	}
}

func recuLoadYamlFiles2JsonString(dir string, single bool) string {
	var files []string
	err := filepath.Walk("v1/config/"+dir, visit(&files))
	if err != nil {
		panic(err)
	}
	var pocs []interface{}
	for _, file := range files {
		var tmp interface{}
		bs, err := os.ReadFile(file)
		if err != nil {
			panic(err)
		}

		err = yaml.Unmarshal(bs, &tmp)
		if err != nil {
			print(file)
			panic(err)
		}

		if tmp == nil {
			continue
		}

		if single {
			pocs = append(pocs, tmp)
		} else {
			pocs = append(pocs, tmp.([]interface{})...)
		}

	}

	jsonstr, err := json.Marshal(pocs)
	if err != nil {
		panic(err)
	}

	return Encode(jsonstr)
}

func main() {
	Key = []byte(os.Getenv("gt_key"))
	fmt.Println("key: " + os.Getenv("gt_key"))
	template := `package pkg

var RandomDir = "/g8kZMwp4oeKsL2in"

func LoadConfig(typ string)[]byte  {
	if typ == "tcp" {
		return FileDecode("%s")
	}else if typ=="http"{
		return FileDecode("%s")
    }else if typ =="port"{
         	return FileDecode("%s")
    }else if typ == "workflow"{
         	return FileDecode("%s")
    }else if typ == "nuclei"{
            return FileDecode("%s")
    }
	return []byte{}
}
`
	template = fmt.Sprintf(template,
		loadYamlFile2JsonString("fingers/tcpfingers.yaml"),
		recuLoadYamlFiles2JsonString("fingers/http", false),
		loadYamlFile2JsonString("port.yaml"),
		loadYamlFile2JsonString("workflows.yaml"),
		recuLoadYamlFiles2JsonString("nuclei", true),
	)
	f, err := os.OpenFile("v1/pkg/templates.go", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	f.WriteString(template)
	f.Sync()
	f.Close()
	println("generate templates.go successfully")
}
