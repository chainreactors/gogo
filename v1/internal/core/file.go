package core

import (
	"bytes"
	"fmt"
	. "getitle/v1/pkg"
	"getitle/v1/pkg/dsl"
	"getitle/v1/pkg/utils"
	. "github.com/chainreactors/files"
	. "github.com/chainreactors/logs"
	"io/ioutil"
	"os"
	"strings"
)

func LoadFile(file *os.File) []byte {
	defer file.Close()
	content, err := ioutil.ReadAll(file)
	if err != nil {
		utils.Fatal(err.Error())
	}
	//if IsBase64(content) {
	//	content = Base64Decode(string(content))
	//}
	//if IsBin(content) {
	//	content = UnFlate(content)
	//}
	return bytes.TrimSpace(content)
}

func newFile(filename string) (*File, error) {
	file, err := NewFile(filename, Opt.Compress, true, false)
	if err != nil {
		return nil, err
	}

	var cursor int

	file.Encoder = func(i []byte) []byte {
		bs := dsl.XorEncode(Flate(i), Key, cursor)
		cursor += len(bs)
		return bs
	}
	return file, nil
}

func initFile(config *Config) error {
	var err error
	// 初始化res文件handler
	if config.Filename != "" {
		Log.Clean = !Log.Clean
		// 创建output的filehandle
		Opt.File, err = newFile(config.Filename)
		if err != nil {
			utils.Fatal(err.Error())
		}
		if Opt.FileOutput == "json" {
			var rescommaflag bool
			Opt.File.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("scan")))
			Opt.File.ClosedAppend = "]}"
			Opt.File.Handler = func(res string) string {
				if rescommaflag {
					// 只有json输出才需要手动添加逗号
					res = "," + res
				}
				if Opt.FileOutput == "json" {
					// 如果json格式输出,则除了第一次输出,之后都会带上逗号
					rescommaflag = true
				}
				return res
			}
		}
		Opt.ExtractFile, err = newFile(config.Filename + "_extract")
	}

	// -af 参数下的启发式扫描结果handler初始化
	if config.SmartFilename != "" {
		Opt.SmartFile, err = newFile(config.SmartFilename)
		if err != nil {
			return err
		}

		Opt.SmartFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("smart")))
		Opt.SmartFile.ClosedAppend = "]}"
	}

	if config.AlivedFilename != "" {
		Opt.AliveFile, err = newFile(config.AlivedFilename)
		if err != nil {
			return err
		}
		Opt.AliveFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("ping")))
		Opt.AliveFile.ClosedAppend = "]}"
	}

	return nil
}

func commaStream(ips []string, comma *bool) string {
	var builder strings.Builder
	for _, ip := range ips {
		if *comma {
			builder.WriteString("," + "\"" + ip + "\"")
		} else {
			builder.WriteString("\"" + ip + "\"")
			*comma = true
		}
	}
	return builder.String()
}

var smartcommaflag bool = false

func writeSmartResult(ips []string) {
	Opt.SmartFile.SafeWrite(commaStream(ips, &smartcommaflag))
	Opt.SmartFile.SafeSync()
}

var pingcommaflag bool = false

func writeAlivedResult(ips []string) {
	Opt.AliveFile.SafeWrite(commaStream(ips, &pingcommaflag))
	Opt.AliveFile.SafeSync()
}

func syncFile() {
	if Opt.File != nil {
		Opt.File.SafeSync()
	}
}

//var winfile = []string{
//	"App_1634884664021088500_EC1B25B2-9453-49EE-A1E2-112B4D539F5",
//	"W2R8219CVYF4_C0679168892B0A822EB17C1421CE7BF",
//}
//var linuxfile = []string{
//	".sess_ha73n80og7veig0pojpp3ltnt",
//	".systemd-private-701215aa8263408d8d44f4507834d77",
//}
