//go:generate go run templates/templates_gen.go -t templates -o pkg/templates.go
package main

import (
	"github.com/chainreactors/gogo/v2/cmd"
	//_ "net/http/pprof"
	"os"
)

func main() {
	//cpufile, _ := os.Create("cpu.prof")
	//pprof.StartCPUProfile(cpufile)
	//go func() {
	//	c := make(chan os.Signal, 2)
	//	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	//
	//	<-c
	//	logs.Log.Importantf("exit signal, save stat and exit")
	//
	//	signal.Stop(c)
	//
	//	pprof.StopCPUProfile()
	//	os.Exit(0)
	//}()
	//
	//go func() {
	//	log.Println(http.ListenAndServe("localhost:6060", nil))
	//}()

	cmd.Gogo()
	os.Exit(0)
}
