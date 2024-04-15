package pkg

import (
	"github.com/chainreactors/fingers/fingers"
)

var (
	FingerEngine *fingers.FingersRules
)

// LoadFinger 加载指纹到全局变量
func LoadFinger() error {
	engine, err := fingers.NewFingersEngine(LoadConfig("http"), LoadConfig("socket"))
	if err != nil {
		return err
	}
	FingerEngine = engine
	return nil
}
