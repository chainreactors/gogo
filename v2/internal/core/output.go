package core

import (
	"encoding/json"
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
	var iscolor bool
	var rd *ResultsData
	var sd *SmartData
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
	case *SmartData:
		sd = data.(*SmartData)
		if filenamef == "clear" {
			sd.Config.Filenamef = filenamef
			outFilename = GetFilename(&sd.Config, "cidr")
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
		outfunc(strings.Join(sd.Data, "\n"))
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

		if outf == "c" {
			iscolor = true
		}

		if outf == "cs" {
			outfunc(rd.ToCobaltStrike())
		} else if outf == "zombie" {
			outfunc(rd.ToZombie())
		} else if outf == "c" || outf == "full" {
			outfunc(rd.ToFormat(iscolor))
		} else if outf == "json" {
			content, err := json.Marshal(rd)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			outfunc(string(content))
		} else if outf == "csv" {
			outfunc(rd.ToCsv())
		} else if outf == "extract" {
			outfunc(rd.ToExtracteds())
		} else {
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
