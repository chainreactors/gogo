package core

import (
	"bytes"
	"github.com/chainreactors/gogo/v1/internal/scan"
	. "github.com/chainreactors/gogo/v1/pkg"
	"github.com/chainreactors/gogo/v1/pkg/utils"
	"io/ioutil"
	"os"
	"strings"
)

const (
	LinuxDefaultThreads   = 4000
	WindowsDefaultThreads = 1000
	ReScanDefaultThreads  = 100
	DefaultIpProbe        = "1,254"
	DefaultPortProbe      = "80"
	SuperSmartPortProbe   = "icmp"
)

type targetConfig struct {
	ip      string
	port    string
	hosts   []string
	fingers Frameworks
}

func (tc *targetConfig) NewResult() *Result {
	result := NewResult(tc.ip, tc.port)
	if tc.hosts != nil {
		if len(tc.hosts) == 1 {
			result.CurrentHost = tc.hosts[0]
		}
		result.HttpHosts = tc.hosts
	}
	if tc.fingers != nil {
		result.Frameworks = tc.fingers
	}

	if scan.RunOpt.SuffixStr != "" && !strings.HasPrefix(scan.RunOpt.SuffixStr, "/") {
		result.Uri = "/" + scan.RunOpt.SuffixStr
	}
	return result
}

// return open: 0, closed: 1, filtered: 2, noroute: 3, denied: 4, down: 5, error_host: 6, unkown: -1

var portstat = map[int]string{
	//0:  "open",
	1:  "closed",
	2:  "filtered|closed",
	3:  "noroute",
	4:  "denied",
	5:  "down",
	6:  "error_host",
	-1: "unknown",
}

type Options struct {
	AliveSum    int
	Noscan      bool
	PluginDebug bool
}

var syncFile = func() {}

func LoadFile(file *os.File) []byte {
	defer file.Close()
	content, err := ioutil.ReadAll(file)
	if err != nil {
		utils.Fatal(err.Error())
	}
	//if IsBase64(content) {
	//	content = Base64Decode(string(content))
	//}
	//if IsBin(content) {
	//	content = UnFlate(content)
	//}
	return bytes.TrimSpace(content)
}
