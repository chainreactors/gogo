package pkg

import (
	"fmt"
	. "github.com/chainreactors/files"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/parsers"
	"regexp"
)

var (
	Win  = utils.IsWin()
	Root = utils.IsRoot()
	//Key  = []byte{}
)

func CompileRegexp(s string) *regexp.Regexp {
	reg, err := regexp.Compile(s)
	if err != nil {
		utils.Fatal(fmt.Sprintf("regexp string error: %s, %s", s, err.Error()))
	}
	return reg
}

func Decode(input string) []byte {
	b := parsers.Base64Decode(input)
	return UnFlate(b)
}

func Encode(input []byte) string {
	s := Flate(input)
	s = XorEncode(s, Key, 0)
	return parsers.Base64Encode(s)
}

func HasPingPriv() bool {
	if Win || Root {
		return true
	}
	return false
}
