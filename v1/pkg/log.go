package pkg

import (
	"fmt"
	"os"
	"path"
	"time"
)

var Log *Logger

func NewLogger(quiet, debug bool) *Logger {
	return &Logger{
		Quiet:   quiet,
		IsDebug: debug,
	}
}

type Logger struct {
	Quiet   bool
	Clean   bool
	IsDebug bool
	LogCh   chan string
	LogFile *File
}

var LogFilename string

func (log *Logger) InitFile() {
	// 初始化进度文件
	_ = os.Remove(path.Join(getExcPath(), ".sock.lock"))
	if !IsExist(".sock.lock") {
		LogFilename = ".sock.lock"
	} else {
		LogFilename = fmt.Sprintf(".%d.unix", time.Now().Unix()-100000)
	}
	var err error
	LogFilename = path.Join(getExcPath(), LogFilename)
	log.LogFile, err = NewFile(LogFilename, false, false)
	if err != nil {
		Log.Warn("cannot create logfile, err:" + err.Error())
		return
	}
	log.LogCh = make(chan string, 100)
}

func (log *Logger) Important(s string) {
	s = fmt.Sprintf("[*] %s , %s\n", s, GetCurtime())
	if !log.Quiet {
		fmt.Print(s)
	}
	if log.LogFile != nil {
		log.LogCh <- s
	}
}

func (log *Logger) Importantf(format string, s ...interface{}) {
	line := fmt.Sprintf("[*] "+format+", "+GetCurtime()+"\n", s...)
	if !log.Quiet {
		fmt.Print(line)
	}
	if log.LogFile != nil {
		log.LogCh <- line
	}
}

func (log *Logger) Default(s string) {
	if !log.Clean {
		fmt.Print(s)
	}
}

func (log *Logger) Error(s string) {
	if !log.Quiet {
		fmt.Println("[-] " + s)
	}
}

func (log *Logger) Errorf(format string, s ...interface{}) {
	if !log.Quiet {
		fmt.Printf("[-] "+format+"\n", s...)
	}
}

func (log *Logger) Warn(s string) {
	if !log.Quiet {
		fmt.Println("[warn] " + s)
	}
}

func (log *Logger) Warnf(format string, s ...interface{}) {
	if !log.Quiet {
		fmt.Printf("[warn] "+format+"\n", s...)
	}
}

func (log *Logger) Debug(s string) {
	if log.IsDebug {
		fmt.Println("[debug] " + s)
	}
}

func (log *Logger) Debugf(format string, s ...interface{}) {
	if log.IsDebug {
		fmt.Printf("[debug] "+format+"\n", s...)
	}
}

func (log *Logger) Close() {
	if log.LogCh != nil {
		close(log.LogCh)
		time.Sleep(time.Microsecond * 200)
	}
}
