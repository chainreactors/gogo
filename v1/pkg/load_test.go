package pkg

import (
	"getitle/v1/pkg/fingers"
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

func TestTeamplate(t *testing.T) {
	a := []string{"aa", "bb", "cc"}
	b := []string{"aa", "bb", "dd"}
	for _, i := range a {
		if i == "cc" {
			a = append(a, b...)
		}
		println(i)
	}
}
