//go:generate go run templates/templates_gen.go -o pkg/templates.go
package main

import "github.com/chainreactors/gogo/v2/cmd"

func main() {
	//f, _ := os.Create("cpu.txt")
	//pprof.StartCPUProfile(f)
	//defer pprof.StopCPUProfile()
	cmd.Gogo()
}
