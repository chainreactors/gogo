//go:generate go run templates/templates_gen.go -t templates -o pkg/templates.go
package main

import (
	"github.com/chainreactors/gogo/v2/cmd"
)

func main() {
	//cpufile, _ := os.Create("cpu.prof")
	//pprof.StartCPUProfile(cpufile)
	//defer pprof.StopCPUProfile()

	cmd.Gogo()
}
