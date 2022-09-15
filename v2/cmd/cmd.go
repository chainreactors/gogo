package cmd

import (
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/jessevdk/go-flags"
	"os"
)

var ver = ""

func Gogo() {
	var runner Runner
	parser := flags.NewParser(&runner, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		if err.(*flags.Error).Type != flags.ErrHelp {
			fmt.Println(err.Error())
		}
		return
	}

	if ok := runner.preInit(); !ok {
		os.Exit(0)
	}
	runner.init()
	runner.run()

	logs.Log.Close(true)
}
