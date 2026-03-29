//go:build !tinygo
// +build !tinygo

package pkg

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils/fileutils"
)

func installFileSyncSignalHandler(file *fileutils.File) {
	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			logs.Log.Debug("save and exit!")
			file.Sync()
			os.Exit(0)
		}()
	}()
}
