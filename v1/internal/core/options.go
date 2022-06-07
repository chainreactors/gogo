package core

import . "getitle/v1/pkg"

type Options struct {
	AliveSum    int
	Noscan      bool
	Compress    bool
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

func (opt *Options) Close() {
	// 关闭管道
	if Opt.dataCh != nil {
		close(Opt.dataCh)
	}
	if Opt.ExtractFile != nil {
		close(Opt.extractCh)
	}
}
