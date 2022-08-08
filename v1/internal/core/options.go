package core

import (
	"bytes"
	"getitle/v1/pkg/utils"
	"io/ioutil"
	"os"
)

const (
	LinuxDefaultThreads   = 4000
	WindowsDefaultThreads = 1000
	ReScanDefaultThreads  = 100
	DefaultIpProbe        = "1,254"
	DefaultPortProbe      = "80"
	SuperSmartPortProbe   = "icmp"
)

type Options struct {
	AliveSum int
	Noscan   bool
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
