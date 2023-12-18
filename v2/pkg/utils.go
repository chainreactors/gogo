package pkg

import (
	"github.com/chainreactors/utils/encode"
	"strings"

	. "github.com/chainreactors/files"
	"github.com/chainreactors/utils/iutils"
)

var (
	Win  = iutils.IsWin()
	Mac  = iutils.IsMac()
	Root = iutils.IsRoot()
	//Key  = []byte{}
)

//func CompileRegexp(s string) *regexp.Regexp {
//	reg, err := regexp.Compile(s)
//	if err != nil {
//		iutils.Fatal(fmt.Sprintf("regexp string error: %s, %s", s, err.Error()))
//	}
//	return reg
//}

func Decode(input string) []byte {
	b := encode.Base64Decode(input)
	return UnFlate(b)
}

func HasPingPriv() bool {
	if Win || Root {
		return true
	}
	return false
}

func CleanSpiltCFLR(s string) []string {
	ss := strings.Split(s, "\n")
	for i := 0; i < len(ss); i++ {
		ss[i] = strings.Trim(ss[i], "\r")
	}
	return ss
}
