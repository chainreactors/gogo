package utils

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

func FileInitialize(filename string) (*os.File, error) {
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

func NewFile(filename string, compress bool) (*File, error) {
	filehandler, err := FileInitialize(filename)
	if err != nil {
		return nil, err
	}
	var file = &File{
		compress:    compress,
		fileHandler: filehandler,
		fileWriter:  bufio.NewWriter(filehandler),
		buf:         bytes.NewBuffer([]byte{}),
	}
	return file, nil
}

type File struct {
	fileHandler *os.File
	fileWriter  *bufio.Writer
	buf         *bytes.Buffer
	compress    bool
}

func (f *File) Write(s string) {
	if f.compress {
		_, err := f.buf.WriteString(s)
		if err != nil {
			println(err.Error())
			os.Exit(0)
		}
		if f.buf.Len() > 4096 {
			f.Sync()
		}
		return
	} else {
		_, _ = f.fileHandler.WriteString(s)
		return
	}
}

func SafeWrite(s string) {

}
func (f *File) SyncWrite(s string) {
	f.Write(s)
	f.Sync()
}

func (f *File) WriteBytes(bs []byte) {
	if f.compress {
		//res = string(utils.Flate([]byte(res)))
		_, err := f.buf.Write(bs)
		if err != nil {
			println(err.Error())
			os.Exit(0)
		}
		if f.buf.Len() > 4096 {
			f.Sync()
		}
		return
	} else {
		_, _ = f.fileHandler.Write(bs)
		return
	}
}

func (f *File) Sync() {
	if f == nil {
		return
	}
	if f.compress && f.fileWriter != nil && f.buf != nil && f.buf.Len() != 0 {
		_, _ = f.fileWriter.Write(Flate(f.buf.Bytes()))
		f.buf.Reset()
		_ = f.fileWriter.Flush()
		_ = f.fileHandler.Sync()
	}
	_ = f.fileHandler.Sync()
	return
}

func (f *File) Close() {
	f.Sync()
	_ = f.fileHandler.Close()
}
