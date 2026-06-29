package core

import (
	"encoding/json"
	"fmt"
	"github.com/chainreactors/utils/fileutils"
	"io"
	"net/http"
	"os"
	"strings"

	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/utils/parsers"
)

func normalizeOutputDelimiter(delimiter string) string {
	if delimiter == "" {
		return "\t"
	}
	return delimiter
}

func outputValues(result *Result, outType, delimiter string) string {
	outs := strings.Split(outType, ",")
	values := make([]string, len(outs))
	for i, out := range outs {
		values[i] = result.Get(out)
	}
	return strings.Join(values, normalizeOutputDelimiter(delimiter)) + "\n"
}

func outputResultsValues(results parsers.GOGOResults, outType, delimiter string) string {
	outs := strings.Split(outType, ",")
	lines := make([]string, 0, len(results))
	seen := make(map[string]struct{}, len(results))
	delimiter = normalizeOutputDelimiter(delimiter)

	for _, result := range results {
		values := make([]string, len(outs))
		for j, out := range outs {
			values[j] = result.Get(out)
		}
		line := strings.Join(values, delimiter)
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

func output(result *Result, outType, delimiter string) string {
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
		out = outputValues(result, outType, delimiter)
	}
	return out
}

func FormatOutput(filename, outFilename, outf, filenamef, delimiter string, filters []string, filterOr bool) error {
	var outfunc func(s string)
	var file io.Reader
	if filename == "stdin" {
		file = os.Stdin
	} else if strings.HasPrefix(filename, "http://") || strings.HasPrefix(filename, "https://") {
		req, err := http.Get(filename)
		if err != nil {
			return err
		}
		defer req.Body.Close()
		file = req.Body
	} else {
		fileHandle, err := fileutils.Open(filename)
		if err != nil {
			return err
		}
		defer fileHandle.Close()
		file = fileHandle
	}

	if filenamef == "auto" {
		filenamef = "clear"
	}

	data := LoadResultFile(file)
	var text string
	var rd *ResultsData
	var sd *SmartResult
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
		return nil
	}

	// 初始化再输出文件
	if outFilename != "" {
		fileHandle, err := fileutils.NewFile(outFilename, fileutils.ModeCreate, false, false)
		if err != nil {
			return err
		}
		fmt.Println("Output filename: " + outFilename)
		defer fileHandle.Close()
		outfunc = func(s string) {
			fileHandle.WriteString(s)
		}
	} else {
		outfunc = func(s string) {
			fmt.Print(s)
		}
	}

	if sd != nil && sd.Data != nil {
		outfunc(strings.Join(sd.List(), "\n"))
		return nil
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
		case "zombie":
			zs := rd.ToZombie()
			marshal, err := json.Marshal(zs)
			if err != nil {
				return err
			}
			outfunc(string(marshal))
		default:
			outfunc(outputResultsValues(rd.Data, outf, delimiter))
		}

	} else if text != "" {
		if outFilename != "" {
			outfunc(text)
		}
	}
	return nil
}

func Usage() string {
	return `

  WIKI: https://chainreactors.github.io/wiki/gogo/
  
  QUICKSTART:
    simple example:
      gogo -i 1.1.1.1/24 -p top2,win,db -ev

    list input spray:
      gogo -l ip.txt -p http 

    stdin input:
      sometool | gogo -L -p http -q | exploit

    smart scan:
      gogo -i 192.168.1.1/16 -m s -p top2,win,db --af

    supersmart scan:
      gogo -i 10.1.1.1/8 -m ss -p top2,win,db --af

    smart+icmp scan:
      gogo -i 192.168.1.1/16 -m s --ping -p top2,win,db --af

    workflow:
      gogo -w 10

  FORMAT:
    standard format:
      gogo -F 1.dat

    json output:
      gogo -F 1.dat -o json -f 1.json

    filter output:
      gogo -F 1.dat --filter frame::redis 
`
}

func Banner() string {
	return fmt.Sprintf(`gogo:%s`, ver)
}
