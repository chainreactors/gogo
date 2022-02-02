package core

import (
	"fmt"
	. "getitle/src/utils"
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

func (log *Logger) Init(file *File) {
	log.LogFile = file
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
		fmt.Println("[+] " + s)
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
	log.LogFile.Close()
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
