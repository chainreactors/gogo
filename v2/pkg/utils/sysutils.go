package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	cwtime = getcwtime()
)

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

func IsRoot() bool {
	if os.Getuid() == 0 {
		return true
	}
	return false
}

func GetFdLimit() int {
	cmd := exec.Command("sh", "-c", "ulimit -n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		println(err.Error())
		return -1
	}
	s := strings.TrimSpace(string(out))
	return ToInt(s)
}

func GetExcPath() string {
	file, _ := exec.LookPath(os.Args[0])
	// 获取包含可执行文件名称的路径
	path, _ := filepath.Abs(file)
	// 获取可执行文件所在目录
	index := strings.LastIndex(path, string(os.PathSeparator))
	ret := path[:index]
	return strings.Replace(ret, "\\", "/", -1) + "/"
}

func Fatal(s string) {
	fmt.Println("[-] " + s)
	os.Exit(0)
}

//func SetFdLimit(i int)bool{
//	//cmd := exec.Command("sh", "-c","ulimit -n " + ToString(i))
//	cmd := exec.Command("ulimit","-n", ToString(i))
//	_,err := cmd.CombinedOutput()
//	if err != nil{
//		println(err.Error())
//		return false
//	}
//	return true
//}
