package core

import (
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
var Datach = make(chan string, 100)
var FileHandle, SmartFileHandle *os.File // 输出文件 handle

var Output string     // 命令行输出格式
var FileOutput string // 文件输出格式

//进度tmp文件
var LogDetach = make(chan string, 100)
var LogFileHandle *os.File
var tmpfilename string

func LoadFile(file *os.File) []string {
	defer file.Close()
	content, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(0)
	}
	text := string(content)
	text = strings.TrimSpace(text)
	return strings.Split(text, "\n")
}

func InitFileHandle(filename string) *os.File {
	var err error
	var filehandle *os.File
	if CheckFileIsExist(filename) { //如果文件存在
		//FileHandle, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, os.ModeAppend) //打开文件
		fmt.Println("[-] File already exists")
		os.Exit(0)
	} else {
		filehandle, err = os.Create(filename) //创建文件
		if err != nil {
			fmt.Println("[-] create file error," + err.Error())
			os.Exit(0)
		}
	}
	return filehandle
}

func InitFile(config utils.Config) {
	// 挂起两个文件操作的goroutine

	// 初始化res文件handler
	if config.Filename != "" {
		Clean = !Clean
		// 创建output的filehandle
		FileHandle = InitFileHandle(config.Filename)

		if FileOutput == "json" && !(Noscan || config.Mod == "sc") {
			writefile(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("scan")))
		}
	}

	// -af 参数下的启发式扫描结果handler初始化
	if config.SmartFilename != "" {
		SmartFileHandle = InitFileHandle(config.SmartFilename)
		writefile(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("smartr")))
	}

	// 初始化进度文件
	if !CheckFileIsExist(".sock.lock") {
		tmpfilename = ".sock.lock"
	} else {
		tmpfilename = fmt.Sprintf(".%s.unix", ToString(time.Now().Unix()))
	}
	_ = os.Remove(".sock.lock")
	LogFileHandle = InitFileHandle(tmpfilename)

	//挂起文件相关协程

	// 进度文件
	go func() {
		for res := range LogDetach {
			_, _ = LogFileHandle.WriteString(res)
			_ = LogFileHandle.Sync()
		}
		_ = LogFileHandle.Close()
		_ = os.Remove(tmpfilename)
	}()

	// res文件
	if FileHandle != nil {
		go func() {
			defer fileclose()
			var commaflag2 bool
			for res := range Datach {
				if commaflag2 {
					res = "," + res
				} else if FileOutput == "json" && !Noscan {
					// 如果json格式输出,则除了第一次输出,之后都会带上逗号
					commaflag2 = true
				}
				writefile(res)
			}
		}()
	}
}

func fileclose() {
	if FileOutput == "json" && !Noscan {
		writefile("]}")
	}

	if SmartFileHandle != nil {
		_, _ = SmartFileHandle.WriteString("]}")
		_ = SmartFileHandle.Close()
	}
	_ = FileHandle.Close()
}

func writefile(res string) {
	if Compress {
		res = string(Flate([]byte(res)))
	}
	_, _ = FileHandle.WriteString(res)
}

var commaflag bool = false

func WriteSmartResult(ips []string) {
	iplists := make([]string, len(ips))
	for i, ip := range ips {
		iplists[i] = "\"" + ip + "\""
	}
	if commaflag {
		writefile(",")
	}
	writefile(strings.Join(iplists, ","))
	commaflag = true
	_ = SmartFileHandle.Sync()
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
	for CheckFileIsExist(basename + ToString(fileint) + ".dat") {
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

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}
