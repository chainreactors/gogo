package pkg

import (
	"fmt"
	. "github.com/chainreactors/files"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/ipcs"
	"github.com/chainreactors/parsers"
	"regexp"
	"sort"
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

func FileDecode(input string) []byte {
	b := parsers.Base64Decode(input)
	b = parsers.XorEncode(b, Key, 0)
	return UnFlate(b)
}

func Encode(input []byte) string {
	s := Flate(input)
	s = parsers.XorEncode(s, Key, 0)
	return parsers.Base64Encode(s)
}

func HasPingPriv() bool {
	if Win || Root {
		return true
	}
	return false
}

func sortIP(ips []string) []string {
	sort.Slice(ips, func(i, j int) bool {
		return ipcs.Ip2Int(ips[i]) < ipcs.Ip2Int(ips[j])
	})
	return ips
}
