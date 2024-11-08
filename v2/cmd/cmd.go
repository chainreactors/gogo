package cmd

import (
	"fmt"
	core2 "github.com/chainreactors/gogo/v2/core"
	"github.com/chainreactors/logs"
	"github.com/jessevdk/go-flags"
	"os"
)

func Gogo() {
	var runner core2.Runner
	parser := flags.NewParser(&runner, flags.Default)
	parser.Usage = core2.Usage()
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
	logs.Log.Important(core2.Banner())
	err = runner.Init()
	if err != nil {
		logs.Log.Error(err.Error())
		return
	}
	runner.Run()

	if runner.Debug {
		// debug模式不会删除.sock.lock
		logs.Log.Close(false)
	} else {
		logs.Log.Close(true)
	}
}
