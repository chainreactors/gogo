package core

import (
	"encoding/json"
	"fmt"
	. "github.com/chainreactors/files"
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"os"
	"strings"
)

func output(result *Result, outType string) string {
	var out string

	switch outType {
	case "color", "c":
		out = result.ColorOutput()
	case "json", "j":
		out = result.JsonOutput()
	case "jsonlines", "jl":
		out = result.JsonOutput() + "\n"
	case "full":
		out = result.FullOutput()
	case "csv":
		out = result.CsvOutput()
	default:
		out = result.ValuesOutput(outType)
	}
	return out
}

func FormatOutput(filename, outFilename, outf, filenamef string, filters []string) {
	var outfunc func(s string)
	var iscolor bool
	var resultsdata *ResultsData
	var smartdata *SmartData
	var extractsdata []*Extracts
	var textdata string
	var file *os.File
	var err error
	if filename == "stdin" {
		file = os.Stdin
	} else {
		file, err = Open(filename)
		if err != nil {
			utils.Fatal(err.Error())
		}
	}

	if filenamef == "auto" {
		filenamef = "clear"
	}

	data := LoadResultFile(file)
	switch data.(type) {
	case *ResultsData:
		resultsdata = data.(*ResultsData)
		fmt.Println(resultsdata.ToConfig())
		if outFilename == "" {
			outFilename = GetFilename(&resultsdata.Config, outf)
		}
	case *SmartData:
		smartdata = data.(*SmartData)
		if outFilename == "" {
			outFilename = GetFilename(&smartdata.Config, "cidr")
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
	if outFilename != "" {
		fileHandle, err := NewFile(outFilename, false, false, false)
		if err != nil {
			utils.Fatal("" + err.Error())
		}
		fmt.Println("Output filename: " + outFilename)
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
			resultsdata.Filter(filter)
		}

		if outf == "c" {
			iscolor = true
		}

		if outf == "cs" {
			outfunc(resultsdata.ToCobaltStrike())
		} else if outf == "zombie" {
			outfunc(resultsdata.ToZombie())
		} else if outf == "c" || outf == "full" {
			outfunc(resultsdata.ToFormat(iscolor))
		} else if outf == "json" {
			content, err := json.Marshal(resultsdata)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			outfunc(string(content))
		} else if outf == "csv" {
			outfunc(resultsdata.ToCsv())
		} else {
			outfunc(resultsdata.ToValues(outf))
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
		if outFilename != "" {
			outfunc(textdata)
		}
	}
}

func Banner() {
}
