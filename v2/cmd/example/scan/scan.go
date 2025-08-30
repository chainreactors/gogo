package main

import (
	"github.com/chainreactors/gogo/v2/engine"
	"github.com/chainreactors/gogo/v2/pkg"
)

func main() {
	result := pkg.NewResult("127.0.0.1", "80")
	engine.Dispatch(result)

	if result.Open {
		println(result.FullOutput())
	} else {
		println(result.GetTarget(), "close")
	}
}
