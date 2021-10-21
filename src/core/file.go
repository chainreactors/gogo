package core

import (
	"encoding/json"
	"fmt"
	. "getitle/src/structutils"
	. "getitle/src/utils"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

//文件输出
var Datach = make(chan string, 100)
var FileHandle, SmartFileHandle *os.File // 输出文件 handle

var Output string     // 命令行输出格式
var FileOutput string // 文件输出格式

//进度tmp文件
var LogDetach = make(chan string, 100)
var LogFileHandle *os.File
var tmpfilename string

var iplists []string

func readTargetFile(targetfile string) []string {

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
	if CheckFileIsExist(filename) { //如果文件存在
		//FileHandle, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, os.ModeAppend) //打开文件
		fmt.Println("[-] File already exists")
		os.Exit(0)
	} else {
		filehandle, err = os.Create(filename) //创建文件
		if err != nil {
			fmt.Println("[-] create file error," + err.Error())
			os.Exit(0)
		}
	}
	return filehandle
}

func CheckFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func initFile(config Config) {
	// 挂起两个文件操作的goroutine
	// 存在文件输出则停止命令行输出

	configstr, err := json.Marshal(config)
	if err != nil {
		println(err.Error())
		os.Exit(0)
	}

	// 初始化res文件handler
	if config.Filename != "" {
		Clean = !Clean
		// 创建output的filehandle
		FileHandle = initFileHandle(config.Filename)

		if FileOutput == "json" && !(Noscan || config.Mod == "sc") {
			_, _ = FileHandle.WriteString(fmt.Sprintf("{\"config\":%s,\"data\":[", configstr))
		}

	}

	// -af 参数下的启发式扫描结果handler初始化
	if config.SmartFilename != "" {
		SmartFileHandle = initFileHandle(config.SmartFilename)
		_, _ = SmartFileHandle.WriteString(fmt.Sprintf("{\"config\":%s,\"data\":[", configstr))
	}

	// 初始化进度文件
	if !CheckFileIsExist(".sock.lock") {
		tmpfilename = ".sock.lock"
	} else {
		tmpfilename = fmt.Sprintf(".%s.unix", ToString(time.Now().Unix()))
	}
	_ = os.Remove(".sock.lock")
	LogFileHandle = initFileHandle(tmpfilename)

	//挂起文件相关协程

	// 进度文件
	go func() {
		for res := range LogDetach {
			_, _ = LogFileHandle.WriteString(res)
			_ = LogFileHandle.Sync()
		}
		_ = LogFileHandle.Close()
		_ = os.Remove(tmpfilename)
	}()

	// res文件
	if FileHandle != nil {
		go func() {
			for res := range Datach {
				_, _ = FileHandle.WriteString(res)
			}
			if FileOutput == "json" && !(Noscan || config.Mod == "sc") {
				_, _ = FileHandle.WriteString("]}")
			}

			if SmartFileHandle != nil {
				for i, ip := range iplists {
					iplists[i] = "\"" + ip + "\""
				}
				_, _ = SmartFileHandle.WriteString(strings.Join(iplists, ","))
				_, _ = SmartFileHandle.WriteString("]}")
			}

			_ = SmartFileHandle.Close()
			_ = FileHandle.Close()

		}()
	}

}
