package core

import (
	"fmt"
	. "github.com/chainreactors/files"
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/parsers/iutils"
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

func FormatOutput(filename, outFilename, outf, filenamef string, filters []string, filterOr bool) {
	var outfunc func(s string)
	var rd *ResultsData
	var sd *SmartResult
	var text string
	var file *os.File
	var err error
	if filename == "stdin" {
		file = os.Stdin
	} else {
		file, err = Open(filename)
		if err != nil {
			iutils.Fatal(err.Error())
		}
	}

	if filenamef == "auto" {
		filenamef = "clear"
	}

	data := LoadResultFile(file)
	switch data.(type) {
	case *ResultsData:
		rd = data.(*ResultsData)
		fmt.Println(rd.ToConfig())
		if filenamef == "clear" {
			config := rd.GetConfig()
			config.Filenamef = filenamef
			outFilename = GetFilename(config, outf)
		}
	case *SmartResult:
		sd = data.(*SmartResult)
		if filenamef == "clear" {
			sd.Config.Filenamef = filenamef
			outFilename = GetFilename(sd.Config, "cidr")
		}
	case []byte:
		text = string(data.([]byte))
	default:
		return
	}

	// 初始化再输出文件
	if outFilename != "" {
		fileHandle, err := NewFile(outFilename, false, false, false)
		if err != nil {
			iutils.Fatal("" + err.Error())
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

	if sd != nil && sd.Data != nil {
		outfunc(strings.Join(sd.List(), "\n"))
		return
	} else if rd != nil && rd.Data != nil {
		if len(filters) > 0 {
			var results parsers.GOGOResults
			if !filterOr {
				results = rd.Data
			}
			for _, filter := range filters {
				if filterOr {
					results = append(results, rd.Filter(filter)...)
				} else {
					results = rd.Data.FilterWithString(filter)
				}
			}
			rd.Data = results
		}

		switch outf {
		case "cs":
			outfunc(rd.ToCobaltStrike())
		case "full":
			outfunc(rd.ToFormat(false))
		case "color", "c":
			outfunc(rd.ToFormat(true))
		case "json":
			outfunc(rd.ToJson())
		case "jl", "jsonline", "jsonlines":
			for _, l := range rd.Data {
				outfunc(l.JsonOutput() + "\n")
			}
		case "csv":
			outfunc(rd.ToCsv())
		case "extract":
			outfunc(rd.ToExtracteds())
		default:
			outfunc(rd.ToValues(outf))
		}

	} else if text != "" {
		if outFilename != "" {
			outfunc(text)
		}
	}
}

func Banner() {
}
