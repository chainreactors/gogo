package utils

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	. "getitle/src/structutils"
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

func NewFile(filename string, compress bool) (*File, error) {
	filehandler, err := FileInitialize(filename)
	if err != nil {
		return nil, err
	}
	var file = &File{
		Filename:    filename,
		compress:    compress,
		fileHandler: filehandler,
		fileWriter:  bufio.NewWriter(filehandler),
		buf:         bytes.NewBuffer([]byte{}),
	}
	return file, nil
}

type File struct {
	Filename    string
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

var fileint = 1

func GetFilename(config *Config, autofile, hiddenfile bool, filepath, outtype string) string {
	var basename string
	var basepath string = filepath
	if filepath == "" {
		basepath = getExcPath()
	}

	if autofile {
		basename = path.Join(basepath, getAutoFilename(config, outtype)+".dat")
	} else if hiddenfile {
		if Win {
			basename = path.Join(basepath, "App_1634884664021088500_EC1B25B2-9453-49EE-A1E2-112B4D539F5.dat")
		} else {
			basename = path.Join(basepath, ".systemd-private-701215aa8263408d8d44f4507834d77")
		}
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
	ports := strings.Replace(config.Ports, ",", "_", -1)
	basename = fmt.Sprintf(".%s_%s_%s_%s", target, ports, config.Mod, outtype)
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
		fmt.Println("[-] " + err.Error())
		os.Exit(0)
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
