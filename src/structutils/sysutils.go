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

func CheckFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
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
