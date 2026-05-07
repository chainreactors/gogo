package core

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/chainreactors/logs"
	"github.com/jessevdk/go-flags"
)

type RunOptions struct {
	Output io.Writer
}

func RunWithArgs(ctx context.Context, args []string, opts RunOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var runner Runner

	output := opts.Output
	if output == nil {
		output = os.Stdout
	}
	if opts.Output != nil {
		oldLog := logs.Log
		logs.Log = logs.NewLogger(oldLog.Level)
		logs.Log.SetOutput(output)
		defer func() {
			logs.Log = oldLog
		}()
	}

	parser := flags.NewParser(&runner, flags.Default&^flags.PrintErrors)
	parser.Usage = Usage()
	if _, err := parser.ParseArgs(args); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			fmt.Fprintln(output, err.Error())
			return nil
		}
		return err
	}

	if ok := runner.Prepare(); !ok {
		return nil
	}
	logs.Log.SetOutput(output)
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	logs.Log.Important(Banner())
	err := runner.Init()
	if err != nil {
		logs.Log.Error(err.Error())
		return err
	}
	runner.Run()
	if runner.Debug {
		logs.Log.Close(false)
	} else {
		logs.Log.Close(true)
	}
	return nil
}
