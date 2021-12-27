package core

import (
	"bufio"
	"errors"
	"fmt"
	. "getitle/src/structutils"
	"getitle/src/utils"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

var Clean = false
var Noscan = false
var Compress = true

//文件输出
var DataCh = make(chan string, 100)
var LogDataCh = make(chan string, 100)

var fileHandle, smartFileHandle, logFileHandle *os.File // 输出文件 handler
var fileWriter, smartfileWriter *bufio.Writer
var Output string     // 命令行输出格式
var FileOutput string // 文件输出格式

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

	// 初始化res文件handler
	if config.Filename != "" {
		Clean = !Clean
		// 创建output的filehandle
		fileHandle, err = InitFileHandle(config.Filename)
		if err != nil {
			return err
		}
		fileWriter = bufio.NewWriter(fileHandle)
		if FileOutput == "json" && !(Noscan || config.Mod == "sc") {
			writefile(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("scan")), fileWriter)
		}
	}

	// -af 参数下的启发式扫描结果handler初始化
	if config.SmartFilename != "" {
		smartFileHandle, err = InitFileHandle(config.SmartFilename)
		if err != nil {
			return err
		}
		smartfileWriter = bufio.NewWriter(smartFileHandle)
		writefile(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("smart")), smartfileWriter)
	}

	// 初始化进度文件
	if !isExist(".sock.lock") {
		tmpfilename = ".sock.lock"
	} else {
		tmpfilename = fmt.Sprintf(".%s.unix", ToString(time.Now().Unix()))
	}
	_ = os.Remove(".sock.lock")

	logFileHandle, err = InitFileHandle(tmpfilename)
	if err != nil {
		return err
	}

	handler()
	return nil
}

func handler() {
	//挂起文件相关协程

	// 进度文件
	go func() {
		for res := range LogDataCh {
			_, _ = logFileHandle.WriteString(res)
			_ = logFileHandle.Sync()
		}
		_ = logFileHandle.Close()
		_ = os.Remove(tmpfilename)
	}()

	// res文件
	if fileHandle != nil {
		go func() {
			defer fileCloser()
			var commaflag2 bool
			for res := range DataCh {
				if commaflag2 {
					res = "," + res
				} else if FileOutput == "json" && !Noscan {
					// 如果json格式输出,则除了第一次输出,之后都会带上逗号
					commaflag2 = true
				}
				writefile(res, fileWriter)
			}
		}()
	}
}

func fileCloser() {
	if FileOutput == "json" && !Noscan {
		writefile("]}", fileWriter)
	}

	_ = fileWriter.Flush()
	if smartFileHandle != nil {
		writefile("]}", smartfileWriter)
		_ = smartfileWriter.Flush()
		_ = smartFileHandle.Close()
	}
	_ = fileHandle.Close()
}

func writefile(res string, file *bufio.Writer) {
	if Compress {
		res = string(utils.Flate([]byte(res)))
	}
	_, _ = file.WriteString(res)
}

var commaflag bool = false

func writeSmartResult(ips []string) {
	iplists := make([]string, len(ips))
	for i, ip := range ips {
		iplists[i] = "\"" + ip + "\""
	}
	if commaflag {
		writefile(",", smartfileWriter)
	}
	writefile(strings.Join(iplists, ","), smartfileWriter)
	commaflag = true
	_ = fileWriter.Flush()
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
	if autofile {
		basename = getAutofile(config, outtype)
	} else if hiddenfile {
		if IsWin() {
			basename = "App_1634884664021088500_EC1B25B2-9453-49EE-A1E2-112B4D539F5"
		} else {
			basename = ".systemd-private-701215aa8263408d8d44f4507834d77"
		}
	} else {
		return ""
	}
	for isExist(basename + ToString(fileint) + ".dat") {
		fileint++
	}
	return basename + ToString(fileint) + ".dat"
}

func getAutofile(config utils.Config, outtype string) string {
	var basename string
	target := strings.Replace(config.GetTargetName(), "/", "_", -1)
	ports := strings.Replace(config.Ports, ",", "_", -1)
	basename = fmt.Sprintf(".%s_%s_%s_%s_", target, ports, config.Mod, outtype)
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
