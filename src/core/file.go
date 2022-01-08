package core

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	. "getitle/src/structutils"
	"getitle/src/utils"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

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

func InitFileHandle(filename string) (*os.File, error) {
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
	if Opt.Compress {
		Opt.comBuf = bytes.NewBuffer([]byte{})
		Opt.smartComBuf = bytes.NewBuffer([]byte{})
	}
	// 初始化res文件handler
	if config.Filename != "" {
		Opt.Clean = !Opt.Clean
		// 创建output的filehandle
		Opt.fileHandle, err = InitFileHandle(config.Filename)
		if err != nil {
			return err
		}
		Opt.fileWriter = bufio.NewWriter(Opt.fileHandle)
		if Opt.FileOutput == "json" && !(Opt.Noscan || config.Mod == "sc") {
			writeFile(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("scan")), false)
		}
	}

	// -af 参数下的启发式扫描结果handler初始化
	if config.SmartFilename != "" {
		Opt.smartFileHandle, err = InitFileHandle(config.SmartFilename)
		if err != nil {
			return err
		}
		Opt.smartfileWriter = bufio.NewWriter(Opt.smartFileHandle)
		writeFile(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("smart")), true)
		smartFileFlush()
	}

	// 初始化进度文件
	if !isExist(".sock.lock") {
		tmpfilename = ".sock.lock"
	} else {
		tmpfilename = fmt.Sprintf(".%s.unix", ToString(time.Now().Unix()))
	}
	_ = os.Remove(".sock.lock")

	Opt.logFileHandle, _ = InitFileHandle(tmpfilename)

	handler()
	return nil
}

func handler() {
	//挂起文件相关协程

	// 进度文件
	go func() {
		for res := range Opt.LogDataCh {
			_, _ = Opt.logFileHandle.WriteString(res)
			_ = Opt.logFileHandle.Sync()
		}
		_ = Opt.logFileHandle.Close()
		_ = os.Remove(tmpfilename)
	}()

	// res文件
	if Opt.fileHandle != nil {
		go func() {
			defer fileCloser()
			var commaflag2 bool
			for res := range Opt.DataCh {
				if commaflag2 {
					res = "," + res
				} else if Opt.FileOutput == "json" && !Opt.Noscan {
					// 如果json格式输出,则除了第一次输出,之后都会带上逗号
					commaflag2 = true
				}
				writeFile(res, false)
			}
		}()
	}
}

func fileCloser() {
	if Opt.FileOutput == "json" && !Opt.Noscan {
		writeFile("]}", false)
	}
	fileFlush()
	_ = Opt.fileHandle.Close()

	if Opt.smartFileHandle != nil {
		writeFile("]}", true)
		smartFileFlush()
		_ = Opt.smartFileHandle.Close()
	}

}

func write(res string, file *bufio.Writer, buf *bytes.Buffer) {
	if Opt.Compress {
		//res = string(utils.Flate([]byte(res)))
		_, err := buf.WriteString(res)
		if err != nil {
			println(err.Error())
			os.Exit(0)
		}
		if buf.Len() > 4096 {
			_, _ = file.Write(utils.Flate(buf.Bytes()))
			buf.Reset()
		}
		return
	} else {
		_, _ = file.WriteString(res)
		return
	}
}

func writeFile(res string, isSmart bool) {
	if isSmart {
		write(res, Opt.smartfileWriter, Opt.smartComBuf)
	} else {
		write(res, Opt.fileWriter, Opt.comBuf)
	}
}

func fileFlush() {
	if Opt.fileWriter != nil {
		if Opt.comBuf != nil {
			_, _ = Opt.fileWriter.Write(utils.Flate(Opt.comBuf.Bytes()))
			Opt.comBuf.Reset()
		}
		_ = Opt.fileWriter.Flush()
	}
}

func smartFileFlush() {
	if Opt.smartfileWriter != nil {
		if Opt.smartComBuf != nil {
			_, _ = Opt.smartfileWriter.Write(utils.Flate(Opt.smartComBuf.Bytes()))
			Opt.smartComBuf.Reset()
		}
		_ = Opt.smartfileWriter.Flush()
	}
}

var commaflag bool = false

func writeSmartResult(ips []string) {
	iplists := make([]string, len(ips))
	for i, ip := range ips {
		iplists[i] = "\"" + ip + "\""
	}
	if commaflag {
		writeFile(",", true)
	}
	writeFile(strings.Join(iplists, ","), true)
	commaflag = true
	smartFileFlush()
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
