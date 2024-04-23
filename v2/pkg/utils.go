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
)

// return open: 0, closed: 1, filtered: 2, noroute: 3, denied: 4, down: 5, error_host: 6, unkown: -1
var PortStat = map[int]string{
	0:  "open",
	1:  "closed",
	2:  "filtered|closed",
	3:  "noroute",
	4:  "denied",
	5:  "down",
	6:  "error_host",
	7:  "icmp",
	8:  "rst",
	-1: "unknown",
}

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
