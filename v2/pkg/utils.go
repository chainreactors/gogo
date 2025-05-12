package pkg

import (
	"fmt"
	"github.com/chainreactors/files"
	"github.com/chainreactors/utils/encode"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/chainreactors/utils/iutils"
)

var (
	Win            = iutils.IsWin()
	Mac            = iutils.IsMac()
	Root           = iutils.IsRoot()
	DefaultMaxSize = 1024 * 16 // 16k
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
	return encode.MustDeflateDeCompress(b)
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

func LoadResource(url string) ([]byte, error) {
	if files.IsExist(url) {
		return ioutil.ReadFile(url)
	} else if strings.HasPrefix(url, "http") {
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		return ioutil.ReadAll(resp.Body)
	} else {
		return nil, fmt.Errorf("invalid resources: %s", url)
	}
}
