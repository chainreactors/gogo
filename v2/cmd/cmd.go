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
	parser.Usage = core.Banner()
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

	if runner.Debug {
		// debug模式不会删除.sock.lock
		logs.Log.Close(false)
	} else {
		logs.Log.Close(true)
	}
}
