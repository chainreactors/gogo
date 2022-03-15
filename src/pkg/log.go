package pkg

import (
	"fmt"
	"os"
	"time"
)

var Log *Logger

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

var LogFilename string

func (log *Logger) InitFile() {
	// 初始化进度文件

	if !IsExist(".sock.lock") {
		LogFilename = ".sock.lock"
	} else {
		LogFilename = fmt.Sprintf(".%d.unix", time.Now().Unix()-100000)
	}
	_ = os.Remove(".sock.lock")
	var err error
	log.LogFile, err = NewFile(LogFilename, false, true)
	if err != nil {
		Log.Warn("cannot create logfile, err:" + err.Error())
		return
	}
	log.LogCh = make(chan string, 100)
}

func (log *Logger) Logging(s string) {
	s = fmt.Sprintf("%s , %s\n", s, GetCurtime())
	if !log.Quiet {
		fmt.Print(s)
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
	time.Sleep(time.Microsecond * 200)
}
