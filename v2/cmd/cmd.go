package cmd

import (
	"fmt"
	"github.com/chainreactors/gogo/v2/internal/core"
	"github.com/chainreactors/logs"
	"github.com/jessevdk/go-flags"
	"os"
)

func Gogo() {
	var runner core.Runner
	parser := flags.NewParser(&runner, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		if err.(*flags.Error).Type != flags.ErrHelp {
			fmt.Println(err.Error())
		}
		return
	}

	if ok := runner.Prepare(); !ok {
		os.Exit(0)
	}
	runner.Init()
	runner.Run()

	logs.Log.Close(true)
}
