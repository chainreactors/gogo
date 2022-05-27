package pkg

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	. "getitle/src/pkg/utils"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
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

func NewFile(filename string, compress, lazy bool) (*File, error) {
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
	fileHandler *os.File
	fileWriter  *bufio.Writer
	buf         *bytes.Buffer
	compress    bool
}

func (f *File) Init() error {
	if f.fileHandler == nil {
		var err error
		f.fileHandler, err = FileInitialize(f.Filename)
		if err != nil {
			return err
		}
		f.fileWriter = bufio.NewWriter(f.fileHandler)
		f.Initialized = true
	}
	return nil
}

func (f *File) Write(s string) {
	if f == nil {
		return
	}

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
	if f == nil {
		return
	}

	_, _ = f.buf.Write(bs)
	if f.buf.Len() > 4096 {
		f.Sync()
	}
}

func (f *File) Sync() {
	if f == nil || f.fileHandler == nil || f.buf.Len() == 0 {
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
	_ = f.fileHandler.Sync()
	return
}

func (f *File) Close() {
	f.Sync()
	_ = f.fileHandler.Close()
}

var fileint = 1

func GetFilename(config *Config, format string, filepath, outtype string) string {
	var basename string
	var basepath string = filepath
	if filepath == "" {
		basepath = getExcPath()
	}

	if format == "auto" {
		basename = path.Join(basepath, "."+getAutoFilename(config, outtype)+".dat")
	} else if format == "hidden" {
		if Win {
			basename = path.Join(basepath, "App_1634884664021088500_EC1B25B2-9453-49EE-A1E2-112B4D539F5.dat")
		} else {
			basename = path.Join(basepath, ".systemd-private-701215aa8263408d8d44f4507834d77")
		}
	} else if format == "clear" {
		basename = path.Join(basepath, getAutoFilename(config, outtype)+".txt")
	} else {
		return ""
	}
	for IsExist(basename + ToString(fileint)) {
		fileint++
	}
	return basename + ToString(fileint)
}

func getAutoFilename(config *Config, outtype string) string {
	var basename string
	target := strings.Replace(config.GetTargetName(), "/", "_", -1)
	target = strings.Replace(target, ":", "", -1)
	target = strings.Replace(target, "\\", "_", -1)
	ports := strings.Replace(config.Ports, ",", "_", -1)
	basename = fmt.Sprintf("%s_%s_%s_%s", target, ports, config.Mod, outtype)
	return basename
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

func Open(filename string) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		Fatal("" + err.Error())
	}
	return f
}

func getExcPath() string {
	file, _ := exec.LookPath(os.Args[0])
	// 获取包含可执行文件名称的路径
	path, _ := filepath.Abs(file)
	// 获取可执行文件所在目录
	index := strings.LastIndex(path, string(os.PathSeparator))
	ret := path[:index]
	return strings.Replace(ret, "\\", "/", -1) + "/"
}
