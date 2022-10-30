package pkg

import (
	"fmt"
	. "github.com/chainreactors/files"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/parsers"
	"os"
	"path"
	"strings"
)

var smartcommaflag bool
var pingcommaflag bool

func WriteSmartResult(file *File, ips []string) {
	if file != nil {
		file.SafeWrite(commaStream(ips, &smartcommaflag))
		file.SafeSync()
	}
}

func WriteAlivedResult(file *File, ips []string) {
	if file != nil {
		file.SafeWrite(commaStream(ips, &pingcommaflag))
		file.SafeSync()
	}
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

func newFile(filename string, compress bool) (*File, error) {
	file, err := NewFile(filename, compress, true, false)
	if err != nil {
		return nil, err
	}

	var cursor int

	file.Encoder = func(i []byte) []byte {
		bs := parsers.XorEncode(Flate(i), Key, cursor)
		cursor += len(bs)
		return bs
	}
	return file, nil
}

func commaStream(ips []string, comma *bool) string {
	//todo 手动实现流式json输出, 通过全局变量flag实现. 后续改成闭包
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

func IsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

//func Open(filename string) *os.File {
//	f, err := os.Open(filename)
//	if err == nil {
//		return f
//	}
//
//	f, err = os.Open(path.Join(GetExcPath(), filename))
//	if err != nil {
//		utils.Fatal(filename + err.Error())
//	}
//	return f
//}

func getAutoFilename(config *Config, outtype string) string {
	var basename string
	target := strings.Replace(config.GetTargetName(), "/", "_", -1)
	target = strings.Replace(target, ":", "", -1)
	target = strings.Replace(target, "\\", "_", -1)
	ports := strings.Replace(config.Ports, ",", "_", -1)
	basename = fmt.Sprintf("%s_%s_%s_%s", target, ports, config.Mod, outtype)
	return basename
}

var fileint = 1

func GetFilename(config *Config, name string) string {
	var basename string
	var basepath string

	if config.FilePath == "" {
		basepath = utils.GetExcPath()
	} else {
		basepath = config.FilePath
	}

	if config.Filename != "" {
		return config.Filename
	}

	if config.Filenamef == "auto" {
		basename = path.Join(basepath, "."+getAutoFilename(config, name)+".dat")
	} else if config.Filenamef == "hidden" {
		if Win {
			basename = path.Join(basepath, "App_1634884664021088500_EC1B25B2-943.dat")
		} else {
			basename = path.Join(basepath, ".systemd-private-701215aa82634")
		}
	} else if config.Filenamef == "clear" {
		basename = path.Join(basepath, getAutoFilename(config, name)+".txt")
	} else {
		return config.Filename
	}
	for IsExist(basename + utils.ToString(fileint)) {
		fileint++
	}
	return basename + utils.ToString(fileint)
}
