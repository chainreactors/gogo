package main

import (
	"getitle/src/cmd"
)

func main() {
	k := "niuzi" // debug
	//f, _ := os.Create("cpu.txt")
	//pprof.StartCPUProfile(f)
	//defer pprof.StopCPUProfile()
	cmd.CMD(k)
}
