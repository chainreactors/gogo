package pkg

import (
	"getitle/src/fingers"
	"testing"
)

func TestLoadWorkFlow(t *testing.T) {
	a, err := fingers.LoadFingers(LoadConfig("http"))
	if err != nil {
		println(err.Error())
	}
	for _, finger := range a {
		err := finger.Compile(portSliceHandler)
		if err != nil {
			println(err.Error())
		}
	}
	b := a.GroupByPort()
	print(a, b)
}
