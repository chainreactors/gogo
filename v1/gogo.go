//go:generate go run pkg/templates_gen.go
package main

import "github.com/chainreactors/gogo/cmd"

func main() {
	//f, _ := os.Create("cpu.txt")
	//pprof.StartCPUProfile(f)
	//defer pprof.StopCPUProfile()
	cmd.CMD()
}
