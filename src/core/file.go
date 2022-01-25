package core

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"getitle/src/scan"
	. "getitle/src/structutils"
	"getitle/src/utils"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func NewFile(filename string, compress bool) (*File, error) {
	filehandler, err := fileInitialize(filename)
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

func (f *File) write(s string) {
	if f.compress {
		_, err := f.buf.WriteString(s)
		if err != nil {
			println(err.Error())
			os.Exit(0)
		}
		if f.buf.Len() > 4096 {
			f.sync()
		}
		return
	} else {
		_, _ = f.fileHandler.WriteString(s)
		return
	}
}

func (f *File) syncWrite(s string) {
	f.write(s)
	f.sync()
}

func (f *File) writeBytes(bs []byte) {
	if f.compress {
		//res = string(utils.Flate([]byte(res)))
		_, err := f.buf.Write(bs)
		if err != nil {
			println(err.Error())
			os.Exit(0)
		}
		if f.buf.Len() > 4096 {
			f.sync()
		}
		return
	} else {
		_, _ = f.fileHandler.Write(bs)
		return
	}
}

func (f *File) sync() {
	if f == nil {
		return
	}
	if f.compress && f.fileWriter != nil && f.buf != nil && f.buf.Len() != 0 {
		_, _ = f.fileWriter.Write(utils.Flate(f.buf.Bytes()))
		f.buf.Reset()
		_ = f.fileWriter.Flush()
		_ = f.fileHandler.Sync()
	}
	_ = f.fileHandler.Sync()
	return
}

func (f *File) close() {
	f.sync()
	_ = f.fileHandler.Close()
}

//进度tmp文件
var tmpfilename string

func LoadFile(file *os.File) []string {
	defer file.Close()
	content, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(0)
	}
	if utils.IsBin(content) {
		content = utils.UnFlate(content)
	}
	text := string(content)
	text = strings.TrimSpace(text)
	return strings.Split(text, "\n")
}

func isExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func fileInitialize(filename string) (*os.File, error) {
	var err error
	var filehandle *os.File
	if isExist(filename) { //如果文件存在
		return nil, errors.New("File already exists")
	} else {
		filehandle, err = os.Create(filename) //创建文件
		if err != nil {
			return nil, err
		}
	}
	return filehandle, err
}

func initFile(config utils.Config) error {
	var err error

	// 初始化res文件handler
	if config.Filename != "" {
		Opt.Clean = !Opt.Clean
		// 创建output的filehandle
		Opt.file, err = NewFile(config.Filename, Opt.Compress)
		if err != nil {
			return err
		}
		scan.RunOpt.ExtractorFile, err = fileInitialize(config.Filename + "_extractor.txt")
		if err != nil {
			return err
		}
		if Opt.FileOutput == "json" && !(Opt.Noscan || config.Mod == "sc") {
			Opt.file.write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("scan")))
		}
	}

	// -af 参数下的启发式扫描结果handler初始化
	if config.SmartFilename != "" {
		Opt.smartFile, err = NewFile(config.SmartFilename, Opt.Compress)
		if err != nil {
			return err
		}
		Opt.smartFile.write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("smart")))
	}

	if config.PingFilename != "" {
		Opt.pingFile, err = NewFile(config.PingFilename, Opt.Compress)
		if err != nil {
			return err
		}
		Opt.pingFile.write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("ping")))
	}

	// 初始化进度文件
	if !isExist(".sock.lock") {
		tmpfilename = ".sock.lock"
	} else {
		tmpfilename = fmt.Sprintf(".%s.unix", ToString(time.Now().Unix()))
	}
	_ = os.Remove(".sock.lock")

	Opt.logFile, err = NewFile(tmpfilename, false)
	if err != nil {
		ConsoleLog("[warn] cannot create logfile, err:" + err.Error())
	}
	handler()
	return nil
}

func handler() {
	//挂起文件相关协程

	// 进度文件
	if Opt.logFile != nil {
		go func() {
			for res := range Opt.LogDataCh {
				Opt.logFile.syncWrite(res)
			}
			Opt.logFile.close()
			_ = os.Remove(tmpfilename)
		}()
	}

	// res文件
	if Opt.file != nil {
		go func() {
			defer fileCloser()
			var commaflag3 bool
			for res := range Opt.DataCh {
				if commaflag3 {
					res = "," + res
				} else if Opt.FileOutput == "json" && !Opt.Noscan {
					// 如果json格式输出,则除了第一次输出,之后都会带上逗号
					commaflag3 = true
				}
				Opt.file.write(res)
			}
		}()
	}
}

func fileCloser() {
	if Opt.FileOutput == "json" && !Opt.Noscan {
		Opt.file.write("]}")
	}
	Opt.file.close()

	if Opt.smartFile != nil {
		Opt.smartFile.write("]}")
		Opt.smartFile.close()
	}

	if Opt.pingFile != nil {
		Opt.pingFile.write("]}")
		Opt.pingFile.close()
	}
}

var commaflag bool = false

func writeSmartResult(ips []string) {
	iplists := make([]string, len(ips))
	for i, ip := range ips {
		iplists[i] = "\"" + ip + "\""
	}
	if commaflag {
		Opt.smartFile.write(",")
	}
	Opt.smartFile.syncWrite(strings.Join(iplists, ","))
	commaflag = true
}

var commaflag2 bool = false

func writePingResult(ips []string) {
	iplists := make([]string, len(ips))
	for i, ip := range ips {
		iplists[i] = "\"" + getIP(ip) + "\""
	}

	if commaflag2 {
		Opt.pingFile.write(",")
	}
	Opt.pingFile.syncWrite(strings.Join(iplists, ","))
	commaflag2 = true
}

//var winfile = []string{
//	"App_1634884664021088500_EC1B25B2-9453-49EE-A1E2-112B4D539F5",
//	"W2R8219CVYF4_C0679168892B0A822EB17C1421CE7BF",
//}
//var linuxfile = []string{
//	".sess_ha73n80og7veig0pojpp3ltnt",
//	".systemd-private-701215aa8263408d8d44f4507834d77",
//}
var fileint = 1

func GetFilename(config utils.Config, autofile, hiddenfile bool, outtype string) string {
	var basename string
	abspath := getExcPath()
	if autofile {
		basename = abspath + getAutofile(config, outtype) + ".dat"
	} else if hiddenfile {
		if IsWin() {
			basename = abspath + "App_1634884664021088500_EC1B25B2-9453-49EE-A1E2-112B4D539F5.dat"
		} else {
			basename = abspath + ".systemd-private-701215aa8263408d8d44f4507834d77"
		}
	} else {
		return ""
	}
	for isExist(basename + ToString(fileint)) {
		fileint++
	}
	return basename + ToString(fileint)
}

func getAutofile(config utils.Config, outtype string) string {
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
