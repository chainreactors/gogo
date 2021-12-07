package structutils

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

var cwtime = getcwtime()

func IsWin() bool {
	os := runtime.GOOS
	if os == "windows" {
		return true
	}
	return false
}

func getcwtime() time.Time {
	dir, _ := os.Getwd()
	dirinfo, _ := os.Stat(dir)
	t := dirinfo.ModTime()
	y, _ := time.ParseDuration("-14368h")
	return t.Add(y)
}

func Chtime(filename string) bool {
	err := os.Chtimes(filename, cwtime, cwtime)
	if err != nil {
		fmt.Println("[-] " + err.Error())
	}
	return true
}
