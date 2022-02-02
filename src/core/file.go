package core

import (
	"fmt"
	. "getitle/src/structutils"
	. "getitle/src/utils"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
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
	if IsBin(content) {
		content = UnFlate(content)
	}
	text := string(content)
	text = strings.TrimSpace(text)
	return strings.Split(text, "\n")
}

func initFile(config Config) error {
	var err error

	// 初始化res文件handler
	if config.Filename != "" {
		Log.Clean = !Log.Clean
		// 创建output的filehandle
		Opt.file, err = NewFile(config.Filename, Opt.Compress)
		if err != nil {
			return err
		}

		if err != nil {
			return err
		}
		if Opt.FileOutput == "json" && !(Opt.Noscan || config.Mod == "sc") {
			Opt.file.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("scan")))
		}
	}

	// -af 参数下的启发式扫描结果handler初始化
	if config.SmartFilename != "" {
		Opt.smartFile, err = NewFile(config.SmartFilename, Opt.Compress)
		if err != nil {
			return err
		}
		Opt.smartFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("smart")))
	}

	if config.PingFilename != "" {
		Opt.pingFile, err = NewFile(config.PingFilename, Opt.Compress)
		if err != nil {
			return err
		}
		Opt.pingFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("ping")))
	}

	// 初始化进度文件
	if !IsExist(".sock.lock") {
		tmpfilename = ".sock.lock"
	} else {
		tmpfilename = fmt.Sprintf(".%s.unix", ToString(time.Now().Unix()))
	}
	_ = os.Remove(".sock.lock")

	Opt.logFile, err = NewFile(tmpfilename, false)
	if err != nil {
		Log.Important("[warn] cannot create logfile, err:" + err.Error())
	} else {
		Log.Init(Opt.logFile)
	}

	handler()
	return nil
}

func handler() {
	//挂起文件相关协程

	// 进度文件
	if Opt.logFile != nil {
		go func() {
			for res := range Log.LogCh {
				Log.LogFile.SyncWrite(res)
			}
			Log.LogFile.Close()
			_ = os.Remove(tmpfilename)
		}()
	}

	// res文件
	if Opt.file != nil {
		go func() {
			defer fileCloser()
			var rescommaflag bool
			for res := range Opt.DataCh {
				if rescommaflag {
					res = "," + res
				} else if Opt.FileOutput == "json" && !Opt.Noscan {
					// 如果json格式输出,则除了第一次输出,之后都会带上逗号
					rescommaflag = true
				}
				Opt.file.Write(res)
			}
		}()

		go func() {
			for res := range Opt.ExtractCh {
				if Opt.extractFile == nil {
					var err error
					Opt.extractFile, err = NewFile(Opt.file.Filename+"_extract", Opt.Compress)
					if err != nil {
						Log.Warn("cannot create extractor result file, " + err.Error())
						return
					}
				}
				Opt.extractFile.Write(res + "\n")
			}

			if Opt.extractFile != nil {
				Opt.extractFile.Close()
			}
		}()
	}
}

func fileCloser() {
	if Opt.FileOutput == "json" && !Opt.Noscan {
		Opt.file.Write("]}")
	}
	Opt.file.Close()
	if Opt.smartFile != nil {
		Opt.smartFile.Write("]}")
		Opt.smartFile.Close()
	}

	if Opt.pingFile != nil {
		Opt.pingFile.Write("]}")
		Opt.pingFile.Close()
	}
}

var smartcommaflag bool = false

func writeSmartResult(ips []string) {
	iplists := make([]string, len(ips))
	for i, ip := range ips {
		iplists[i] = "\"" + ip + "\""
	}
	if smartcommaflag {
		Opt.smartFile.Write(",")
	} else {
		smartcommaflag = true
	}
	Opt.smartFile.SyncWrite(strings.Join(iplists, ","))
}

var pingcommaflag bool = false

func writePingResult(ips []string) {
	iplists := make([]string, len(ips))
	for i, ip := range ips {
		iplists[i] = "\"" + getIP(ip) + "\""
	}

	if pingcommaflag {
		Opt.pingFile.Write(",")
	} else {
		pingcommaflag = true
	}
	Opt.pingFile.SyncWrite(strings.Join(iplists, ","))
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

func GetFilename(config Config, autofile, hiddenfile bool, outtype string) string {
	var basename string
	var basepath string
	if Opt.FilePath == "" {
		basepath = getExcPath()
	} else {
		basepath = Opt.FilePath
	}
	if autofile {
		basename = path.Join(basepath, getAutoFilename(config, outtype)+".dat")
	} else if hiddenfile {
		if IsWin() {
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

func getAutoFilename(config Config, outtype string) string {
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
