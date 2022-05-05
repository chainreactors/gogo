package core

import (
	"bytes"
	"fmt"
	. "getitle/src/pkg"
	"io/ioutil"
	"os"
	"strings"
)

func LoadFile(file *os.File) []byte {
	defer file.Close()
	content, err := ioutil.ReadAll(file)
	if err != nil {
		Fatal(err.Error())
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
		Opt.File, err = NewFile(config.Filename, Opt.Compress, true)
		if err != nil {
			Log.Warn(err.Error())
		}

		if err != nil {
			return err
		}
		if Opt.FileOutput == "json" {
			Opt.File.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("scan")))
		}
	}

	// -af 参数下的启发式扫描结果handler初始化
	if config.SmartFilename != "" {
		Opt.SmartFile, err = NewFile(config.SmartFilename, Opt.Compress, true)
		if err != nil {
			return err
		}
		Opt.SmartFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("smart")))
	}

	if config.PingFilename != "" {
		Opt.AliveFile, err = NewFile(config.PingFilename, Opt.Compress, true)
		if err != nil {
			return err
		}
		Opt.AliveFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("ping")))
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
			err := os.Remove(LogFilename)
			if err != nil {
				Log.Warn(err.Error())
			}
		}()
	}

	if Opt.File == nil {
		return
	}

	// res文件
	go func() {
		defer fileCloser()
		var rescommaflag bool
		for res := range Opt.dataCh {
			if !Opt.File.Initialized {
				err := Opt.File.Init()
				if err != nil {
					Log.Warn(err.Error())
				}
			}

			if rescommaflag {
				// 只有json输出才需要手动添加逗号
				res = "," + res
			}
			if Opt.FileOutput == "json" {
				// 如果json格式输出,则除了第一次输出,之后都会带上逗号
				rescommaflag = true
			}
			Opt.File.Write(res)
		}
	}()

	go func() {
		for res := range Opt.extractCh {
			if Opt.ExtractFile == nil {
				var err error
				Opt.ExtractFile, err = NewFile(Opt.File.Filename+"_extract", Opt.Compress, false)
				if err != nil {
					Log.Warn("cannot create extractor result File, " + err.Error())
					return
				}
			}
			Opt.ExtractFile.Write(res + "\n")
		}

		if Opt.ExtractFile != nil {
			Opt.ExtractFile.Close()
		}
	}()
}

func fileCloser() {
	if Opt.File != nil {
		if Opt.FileOutput == "json" {
			Opt.File.Write("]}")
		}
		Opt.File.Close()
	}

	if Opt.SmartFile != nil {
		Opt.SmartFile.Write("]}")
		Opt.SmartFile.Close()
	}

	if Opt.AliveFile != nil {
		Opt.AliveFile.Write("]}")
		Opt.AliveFile.Close()
	}
}

var smartcommaflag bool = false

func writeSmartResult(ips []string) {
	if !Opt.SmartFile.Initialized {
		err := Opt.SmartFile.Init()
		if err != nil {
			Log.Warn(err.Error())
			return
		}
	}

	iplists := make([]string, len(ips))
	for i, ip := range ips {
		iplists[i] = "\"" + ip + "\""
	}
	if smartcommaflag {
		Opt.SmartFile.Write(",")
	} else {
		smartcommaflag = true
	}
	Opt.SmartFile.SyncWrite(strings.Join(iplists, ","))
}

var pingcommaflag bool = false

func writePingResult(ips []string) {
	if !Opt.AliveFile.Initialized {
		err := Opt.AliveFile.Init()
		if err != nil {
			Log.Warn(err.Error())
			return
		}
	}
	iplists := make([]string, len(ips))
	for i, ip := range ips {
		iplists[i] = "\"" + getIP(ip) + "\""
	}

	if pingcommaflag {
		Opt.AliveFile.Write(",")
	} else {
		pingcommaflag = true
	}
	Opt.AliveFile.SyncWrite(strings.Join(iplists, ","))
}

//var winfile = []string{
//	"App_1634884664021088500_EC1B25B2-9453-49EE-A1E2-112B4D539F5",
//	"W2R8219CVYF4_C0679168892B0A822EB17C1421CE7BF",
//}
//var linuxfile = []string{
//	".sess_ha73n80og7veig0pojpp3ltnt",
//	".systemd-private-701215aa8263408d8d44f4507834d77",
//}
