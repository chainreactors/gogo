package cmd

import (
	"fmt"
	"github.com/chainreactors/gogo/v2/core"
	"github.com/chainreactors/logs"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func init() {
	log.SetOutput(ioutil.Discard)
}

func Gogo() {
	var runner core.Runner
	defer os.Exit(0)
	parser := flags.NewParser(&runner, flags.Default)
	parser.Usage = core.Usage()
	_, err := parser.Parse()
	if err != nil {
		if err.(*flags.Error).Type != flags.ErrHelp {
			fmt.Println(err.Error())
		}
		return
	}
	defer time.Sleep(100 * time.Millisecond)
	if ok := runner.Prepare(); !ok {
		os.Exit(0)
	}
	logs.Log.Important(core.Banner())
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
