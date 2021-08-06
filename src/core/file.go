package core

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func ReadTargetFile(targetfile string) []string {

	file, err := os.Open(targetfile)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(0)
	}
	defer file.Close()
	targetb, _ := ioutil.ReadAll(file)
	targetstr := strings.TrimSpace(string(targetb))
	targetstr = strings.Replace(targetstr, "\r", "", -1)
	targets := strings.Split(targetstr, "\n")
	return targets
}

func initFileHandle(filename string) *os.File {
	var err error
	var filehandle *os.File
	if checkFileIsExist(filename) { //如果文件存在
		//FileHandle, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, os.ModeAppend) //打开文件
		fmt.Println("[-] File already exists")
		os.Exit(0)
	} else {
		filehandle, err = os.Create(filename) //创建文件
		if err != nil {
			os.Exit(0)
		}
	}
	return filehandle
}

func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func initFile(filename string) {
	// 挂起两个文件操作的goroutine

	// 存在文件输出则停止命令行输出
	if filename != "" {
		Clean = !Clean
		// 创建output的filehandle
		FileHandle = initFileHandle(filename)
		if FileOutput == "json" && !Noscan {
			_, _ = FileHandle.WriteString("[")
		}

	}

	_ = os.Remove(".sock.lock")
	LogFileHandle = initFileHandle(".sock.lock")
	//go write2File(FileHandle, Datach)
	if FileHandle != nil {
		go func() {
			for res := range Datach {
				_, _ = FileHandle.WriteString(res)
			}
			if FileOutput == "json" && !Noscan {
				_, _ = FileHandle.WriteString("]")
			}
			_ = FileHandle.Close()

		}()
	}

	go func() {
		for res := range LogDetach {
			_, _ = LogFileHandle.WriteString(res)
			_ = LogFileHandle.Sync()
		}
		_ = LogFileHandle.Close()
		_ = os.Remove(".sock.lock")
	}()
}
