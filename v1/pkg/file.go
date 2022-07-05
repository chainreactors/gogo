package pkg

import (
	"bufio"
	"bytes"
	"errors"
	"os"
)

func IsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func CreateFile(filename string) (*os.File, error) {
	var err error
	var filehandle *os.File
	if IsExist(filename) { //如果文件存在
		return nil, errors.New("File already exists")
	} else {
		filehandle, err = os.Create(filename) //创建文件
		if err != nil {
			return nil, err
		}
	}
	return filehandle, err
}

func AppendFile(filename string) (*os.File, error) {
	var err error
	var filehandle *os.File
	if IsExist(filename) { //如果文件存在
		filehandle, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
	} else {
		filehandle, err = os.Create(filename) //创建文件
		if err != nil {
			return nil, err
		}
	}
	return filehandle, err
}

func NewFile(filename string, compress, lazy, append bool) (*File, error) {
	var file = &File{
		Filename: filename,
		compress: compress,
		buf:      bytes.NewBuffer([]byte{}),
	}
	if !lazy {
		err := file.Init()
		if err != nil {
			return nil, err
		}
	}

	return file, nil
}

type File struct {
	Filename    string
	Initialized bool
	FileHandler *os.File
	fileWriter  *bufio.Writer
	buf         *bytes.Buffer
	compress    bool
	append      bool
}

func (f *File) Init() error {
	if f.FileHandler == nil {
		var err error
		// 防止初始化失败之后重复初始化, flag提前设置为true
		f.Initialized = true

		if f.append {
			f.FileHandler, err = AppendFile(f.Filename)
		} else {
			f.FileHandler, err = CreateFile(f.Filename)
		}
		if err != nil {
			return err
		}
		f.fileWriter = bufio.NewWriter(f.FileHandler)
	}
	return nil
}

func (f *File) Write(s string) {
	_, _ = f.buf.WriteString(s)
	if f.buf.Len() > 4096 {
		f.Sync()
	}
	return
}

func (f *File) SyncWrite(s string) {
	f.Write(s)
	f.Sync()
}

func (f *File) WriteBytes(bs []byte) {
	_, _ = f.buf.Write(bs)
	if f.buf.Len() > 4096 {
		f.Sync()
	}
}

func (f *File) Sync() {
	if f.FileHandler == nil || f.buf.Len() == 0 {
		return
	}

	if f.compress {
		_, _ = f.fileWriter.Write(Flate(f.buf.Bytes()))
	} else {
		_, _ = f.fileWriter.Write(f.buf.Bytes())
	}
	Log.Debugf("sync %d bytes to %s", f.buf.Len(), f.Filename)
	f.buf.Reset()
	_ = f.fileWriter.Flush()
	_ = f.FileHandler.Sync()
	return
}

func (f *File) Close() {
	if f.FileHandler == nil {
		return
	}
	f.Sync()
	_ = f.FileHandler.Close()
}

func HasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}
