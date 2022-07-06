package core

import (
	. "github.com/chainreactors/files"
)

type Options struct {
	AliveSum    int
	Noscan      bool
	Compress    bool
	File        *File
	SmartFile   *File
	ExtractFile *File
	AliveFile   *File
	//dataCh      chan string
	//extractCh   chan string
	Output     string
	FileOutput string
	FilePath   string
}

func (opt *Options) Close() {
	if Opt.File != nil {
		Opt.File.Close()
	}
	if Opt.SmartFile != nil {
		Opt.SmartFile.Close()
	}
	if Opt.AliveFile != nil {
		Opt.AliveFile.Close()
	}
	if Opt.ExtractFile != nil {
		Opt.ExtractFile.Close()
	}
}
