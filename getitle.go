//go:generate go run src/pkg/templates_gen.go
package main

import "getitle/src/cmd"

func main() {
	//f, _ := os.Create("cpu.txt")
	//pprof.StartCPUProfile(f)
	//defer pprof.StopCPUProfile()
	cmd.CMD()
}
