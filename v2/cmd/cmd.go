package cmd

import (
	"context"
	"fmt"
	"github.com/chainreactors/gogo/v2/core"
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
	defer os.Exit(0)
	err := core.RunWithArgs(context.Background(), os.Args[1:], core.RunOptions{})
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); !ok || flagsErr.Type != flags.ErrHelp {
			fmt.Println(err.Error())
		}
		return
	}
	time.Sleep(100 * time.Millisecond)
}
