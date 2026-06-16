package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/chainreactors/logs"
	"github.com/jessevdk/go-flags"
)

type RunOptions struct {
	Output     io.Writer
	BeforeInit func() error
	AfterInit  func() error
}

func Help() string {
	var runner Runner
	parser := flags.NewParser(&runner, flags.Default&^flags.PrintErrors)
	parser.Usage = Usage()
	var buf bytes.Buffer
	parser.WriteHelp(&buf)
	return buf.String()
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

	ok, err := runner.Prepare()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	logs.Log.SetOutput(output)
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	logs.Log.Important(Banner())
	if opts.BeforeInit != nil {
		if err := opts.BeforeInit(); err != nil {
			logs.Log.Error(err.Error())
			return err
		}
	}
	err = runner.Init()
	if err != nil {
		logs.Log.Error(err.Error())
		return err
	}
	if opts.AfterInit != nil {
		if err := opts.AfterInit(); err != nil {
			logs.Log.Error(err.Error())
			return err
		}
	}
	runner.Config.Ctx = ctx
	if err := runner.Run(); err != nil {
		return err
	}
	if runner.Debug {
		logs.Log.Close(false)
	} else {
		logs.Log.Close(true)
	}
	return nil
}
