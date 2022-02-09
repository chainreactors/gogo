package core

import (
	"bytes"
	"fmt"
	. "getitle/src/pkg"
	"io/ioutil"
	"os"
	"strings"
)

//进度tmp文件
var tmpfilename string

func LoadFile(file *os.File) []byte {
	defer file.Close()
	content, err := ioutil.ReadAll(file)
	if err != nil {
		Panic("[-] " + err.Error())
	}
	if IsBase64(content) {
		content = Base64Decode(string(content))
	}
	if IsBin(content) {
		content = UnFlate(content)
	}
	return bytes.TrimSpace(content)
}

func initFile(config *Config) error {
	var err error
	Opt.dataCh = make(chan string, 100)
	Opt.extractCh = make(chan string, 100)
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
		Opt.aliveFile, err = NewFile(config.PingFilename, Opt.Compress)
		if err != nil {
			return err
		}
		Opt.aliveFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("ping")))
	}

	handler()
	return nil
}

func handler() {
	//挂起文件相关协程

	// 进度文件
	if Log.LogFile != nil {
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
			for res := range Opt.dataCh {
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
			for res := range Opt.extractCh {
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

	if Opt.aliveFile != nil {
		Opt.aliveFile.Write("]}")
		Opt.aliveFile.Close()
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
		Opt.aliveFile.Write(",")
	} else {
		pingcommaflag = true
	}
	Opt.aliveFile.SyncWrite(strings.Join(iplists, ","))
}

//var winfile = []string{
//	"App_1634884664021088500_EC1B25B2-9453-49EE-A1E2-112B4D539F5",
//	"W2R8219CVYF4_C0679168892B0A822EB17C1421CE7BF",
//}
//var linuxfile = []string{
//	".sess_ha73n80og7veig0pojpp3ltnt",
//	".systemd-private-701215aa8263408d8d44f4507834d77",
//}
