//go:generate go run templates/templates_gen.go -t templates -o pkg/templates.go
package main

import (
	"github.com/chainreactors/gogo/v2/cmd"
	"os"
	//_ "net/http/pprof"
)

func main() {
	//cpufile, _ := os.Create("cpu.prof")
	//pprof.StartCPUProfile(cpufile)
	//defer pprof.StopCPUProfile()
	//go func() {
	//	http.ListenAndServe("localhost:6060", nil)
	//}()
	cmd.Gogo()
	os.Exit(0)
}
