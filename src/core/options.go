package core

import . "getitle/src/pkg"

type Options struct {
	AliveSum    int
	Noscan      bool
	Compress    bool
	Debug       bool
	File        *File
	SmartFile   *File
	ExtractFile *File
	AliveFile   *File
	dataCh      chan string
	extractCh   chan string
	Output      string
	FileOutput  string
	FilePath    string
}

var Log *Logger

func (opt *Options) Close() {
	// 关闭管道
	if Opt.dataCh != nil {
		close(Opt.dataCh)
	}
	if Opt.ExtractFile != nil {
		close(Opt.extractCh)
	}
}
