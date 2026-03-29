//go:build tinygo
// +build tinygo

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/chainreactors/gogo/v2/core"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/rem/x/netdev"
	"github.com/chainreactors/rem/x/netdev/native"
)

func main() {
	registerNetdev()
	runTinyGo()
}

//go:noinline
func registerNetdev() {
	netdev.UseNetdev(native.New())
}

//go:noinline
func runTinyGo() {
	runner, showHelp, err := parseRunnerArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		printUsage(os.Stderr)
		os.Exit(2)
	}
	if showHelp {
		printUsage(os.Stdout)
		return
	}

	defer time.Sleep(100 * time.Millisecond)

	if ok := runner.Prepare(); !ok {
		return
	}

	logs.Log.Important(core.Banner())
	if err := runner.Init(); err != nil {
		logs.Log.Error(err.Error())
		closeLogger(runner)
		return
	}

	runner.Run()
	closeLogger(runner)
}

func closeLogger(runner *core.Runner) {
	if runner.Debug {
		logs.Log.Close(false)
		return
	}
	logs.Log.Close(true)
}
