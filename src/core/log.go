package core

import (
	"fmt"
	. "getitle/src/pkg"
	"os"
	"time"
)

func NewLogger(quiet bool) *Logger {
	return &Logger{
		Quiet: quiet,
	}
}

type Logger struct {
	Quiet   bool
	Clean   bool
	LogCh   chan string
	LogFile *File
}

func (log *Logger) InitFile() {
	// 初始化进度文件
	if !IsExist(".sock.lock") {
		tmpfilename = ".sock.lock"
	} else {
		tmpfilename = fmt.Sprintf(".%d.unix", time.Now().Unix()-100000)
	}
	_ = os.Remove(".sock.lock")
	var err error
	log.LogFile, err = NewFile(tmpfilename, false)
	if err != nil {
		Log.Warn("cannot create logfile, err:" + err.Error())
		return
	}
	log.LogCh = make(chan string, 100)
}

func (log *Logger) Logging(s string) {
	s = fmt.Sprintf("%s , %s", s, GetCurtime())
	if !log.Quiet {
		fmt.Println(s)
		return
	}
	if log.LogFile != nil {
		log.LogCh <- s
	}
}

func (log *Logger) Important(s string) {
	if !log.Quiet {
		fmt.Println("[*] " + s)
	}
}

func (log *Logger) Default(s string) {
	if !log.Clean {
		fmt.Println(s)
	}
}

func (log *Logger) Error(s string) {
	if !log.Quiet {
		fmt.Println("[-] " + s)
	}
}

func (log *Logger) Warn(s string) {
	if !log.Quiet {
		fmt.Println("[warn] " + s)
	}
}

func (log *Logger) Close() {
	close(log.LogCh)
}

//func progressLog(s string) {
//	s = fmt.Sprintf("%s , %s", s, GetCurtime())
//	if !Opt.Quiet {
//		// 如果指定了-q参数,则不在命令行输出进度
//		fmt.Println(s)
//		return
//	}
//
//	if Opt.logFile != nil {
//		Opt.LogDataCh <- s
//	}
//}
//
//func ConsoleLog(s string) {
//	if !Opt.Quiet {
//		fmt.Println(s)
//	}
//}
//
