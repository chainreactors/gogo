package core

import (
	"encoding/json"
	"fmt"
	. "getitle/v1/pkg"
	"getitle/v1/pkg/utils"
	. "github.com/chainreactors/files"
	"os"
	"strings"
)

func output(result *Result, outType string) string {
	var out string

	switch outType {
	case "color", "c":
		out = ColorOutput(result)
	case "json", "j":
		out = JsonOutput(result)
	case "jsonlines", "jl":
		out = JsonOutput(result) + "\n"
	case "full":
		out = FullOutput(result)
	default:
		out = ValuesOutput(result, outType)
	}
	return out
}

func FormatOutput(filename string, outputfile string, autofile, isfocus bool, filters []string) {
	var outfunc func(s string)
	var iscolor bool
	var resultsdata *ResultsData
	var smartdata *SmartData
	var extractsdata []*Extracts
	var textdata string
	var file *os.File
	if filename == "stdin" {
		file = os.Stdin
	} else {
		file = Open(filename)
	}

	var fileformat string
	if autofile {
		fileformat = "clear"
	}

	data := LoadResultFile(file)
	switch data.(type) {
	case *ResultsData:
		resultsdata = data.(*ResultsData)
		fmt.Println(resultsdata.ToConfig())
		if outputfile == "" {
			outputfile = GetFilename(&resultsdata.Config, fileformat, Opt.FilePath, Opt.Output)
		}
	case *SmartData:
		smartdata = data.(*SmartData)
		if outputfile == "" {
			outputfile = GetFilename(&smartdata.Config, fileformat, Opt.FilePath, "cidr")
		}
	case []*Extracts:
		extractsdata = data.([]*Extracts)
		//ConsoleLog("parser extracts successfully")
	case []byte:
		textdata = string(data.([]byte))
	default:
		return
	}

	// 初始化再输出文件
	if outputfile != "" {
		fileHandle, err := NewFile(outputfile, false, false, false)
		if err != nil {
			utils.Fatal("" + err.Error())
		}
		fmt.Println("Output filename: " + outputfile)
		defer fileHandle.Close()
		outfunc = func(s string) {
			fileHandle.Write(s)
		}
	} else {
		outfunc = func(s string) {
			fmt.Print(s)
		}
	}

	if smartdata != nil && smartdata.Data != nil {
		outfunc(strings.Join(smartdata.Data, "\n"))
		return
	} else if resultsdata != nil && resultsdata.Data != nil {
		for _, filter := range filters {
			// 过滤指定数据
			if strings.Contains(filter, "::") {
				kv := strings.Split(filter, "::")
				resultsdata.Data = resultsdata.Data.Filter(kv[0], kv[1], "::")
			} else if strings.Contains(filter, "==") {
				kv := strings.Split(filter, "==")
				resultsdata.Data = resultsdata.Data.Filter(kv[0], kv[1], "==")
			}
		}

		if Opt.Output == "c" {
			iscolor = true
		}

		if Opt.Output == "cs" {
			outfunc(resultsdata.ToCobaltStrike())
		} else if Opt.Output == "zombie" {
			outfunc(resultsdata.ToZombie())
		} else if Opt.Output == "c" || Opt.Output == "full" {
			outfunc(resultsdata.ToFormat(iscolor))
		} else if Opt.Output == "json" {
			content, err := json.Marshal(resultsdata)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			outfunc(string(content))
		} else {
			outfunc(resultsdata.ToValues(Opt.Output, isfocus))
		}
	} else if extractsdata != nil {
		for _, extracts := range extractsdata {
			var s string
			s += fmt.Sprintf("[+] %s\n", extracts.Target)
			for _, extract := range extracts.Extractors {
				s += fmt.Sprintf(" \t * %s \n\t\t", extract.Name)
				s += strings.Join(extract.ExtractResult, "\n\t\t") + "\n"
			}
			fmt.Println(s)
		}
	} else if textdata != "" {
		if outputfile != "" {
			outfunc(textdata)
		}
	}
}

func Banner() {
}
