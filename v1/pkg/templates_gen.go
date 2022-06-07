//go:build ignore

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
		panic(err.Error())
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

func recuLoadYamlFiles2JsonString(dir string) string {
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
			panic(err)
		}
		pocs = append(pocs, tmp)
	}

	jsonstr, err := json.Marshal(pocs)
	if err != nil {
		panic(err)
	}

	return Encode(jsonstr)
}

func main() {

	template := `package pkg

var RandomDir = "/g8kZMwp4oeKsL2in"

func LoadConfig(typ string)[]byte  {
	if typ == "tcp" {
		return Decode("%s")
	}else if typ=="http"{
		return Decode("%s")
    }else if typ =="port"{
         	return Decode("%s")
    }else if typ == "workflow"{
         	return Decode("%s")
    }else if typ == "nuclei"{
            return Decode("%s")
    }
	return []byte{}
}
`
	template = fmt.Sprintf(template,
		loadYamlFile2JsonString("fingers/tcpfingers.yaml"),
		loadYamlFile2JsonString("fingers/httpfingers.yaml"),
		loadYamlFile2JsonString("port.yaml"),
		loadYamlFile2JsonString("workflows.yaml"),
		recuLoadYamlFiles2JsonString("nuclei"),
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
