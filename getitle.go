//go:generate go run v1/pkg/templates_gen.go
package main

import "getitle/v1/cmd"

func main() {
	//f, _ := os.Create("cpu.txt")
	//pprof.StartCPUProfile(f)
	//defer pprof.StopCPUProfile()
	cmd.CMD()
}
