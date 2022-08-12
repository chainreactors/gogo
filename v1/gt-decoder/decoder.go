package main

import (
	"flag"
	"github.com/chainreactors/gogo/v1/internal/core"
	"github.com/chainreactors/gogo/v1/pkg"
	"github.com/chainreactors/logs"
)

type decodeOptions struct {
	xor_key     string
	filename    string
	outfilename string
	autofile    bool
	output      string
}

func main() {
	var opt decodeOptions
	flag.StringVar(&opt.xor_key, "k", "", "key")
	flag.StringVar(&opt.filename, "F", "", "input filename")
	flag.StringVar(&opt.outfilename, "f", "", "output filename")
	flag.BoolVar(&opt.autofile, "af", false, "auto output filename")
	flag.StringVar(&opt.output, "o", "full", "output type")

	flag.Parse()

	var filef string
	if opt.filename == "" {
		logs.Log.Error("please input -F filename")
		return
	}
	if opt.autofile {
		filef = "auto"
	}
	pkg.Key = []byte(opt.xor_key)
	logs.Log.Info("key: " + opt.xor_key)
	core.FormatOutput(opt.filename, opt.outfilename, opt.output, filef, nil)
}
