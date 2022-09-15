package plugin

import (
	"encoding/hex"
	"github.com/chainreactors/gogo/v2/pkg"
	"strconv"
	"strings"
)

// -default
var (
	NetbiosItemType map[string]string
	GroupNames      map[string]string
	UniqueNames     map[string]string
)

func Byte2Int(input []byte) (int, error) {
	encodedStr := hex.EncodeToString(input)
	output, err := strconv.Atoi(encodedStr)
	return output, err
}

func init() {
	UniqueNames = map[string]string{
		"\x00": "Workstation Service",
		"\x03": "Messenger Service",
		"\x06": "RAS Server Service",
		"\x1F": "NetDDE Service",
		"\x20": "File Server Service",
		"\x21": "RAS Client Service",
		"\xBE": "Network Monitor Agent",
		"\xBF": "Network Monitor Application",
		"\x1D": "Master Browser",
		"\x1B": "Domain Master Browser",
	}

	GroupNames = map[string]string{
		"\x00": "Domain Name",
		"\x1C": "Domain Controllers",
		"\x1E": "Browser Service Elections",
	}

	NetbiosItemType = map[string]string{
		"\x01\x00": "NetBIOS computer name",
		"\x02\x00": "NetBIOS domain name",
		"\x03\x00": "DNS computer name",
		"\x04\x00": "DNS domain name",
		"\x05\x00": "DNS tree name",
		"\x07\x00": "Time stamp",
	}
}

var nbtdata = pkg.Decode("SktjYGBgZAADBWdvR7yAgUGRgREAAAD//w==")

func nbtScan(result *pkg.Result) {
	var Share bool = false
	var DC bool = false
	result.Protocol = "udp"
	result.Port = "137"
	target := result.GetTarget()

	conn, err := pkg.NewSocket("udp", target, RunOpt.Delay*2)
	if err != nil {
		return
	}
	defer conn.Close()

	reply, err := conn.Request(nbtdata, 1024)
	if err != nil {
		result.Error = err.Error()
		return
	}

	result.Open = true
	if len(reply) <= 58 {
		return
	}

	num, err := Byte2Int(reply[56:57])
	if err != nil {
		result.Error = err.Error()
		return
	}

	var name, group, unique string
	var flag_bit []byte
	data := reply[57:]
	for i := 0; i < num; i++ {
		name = string(data[18*i : 18*i+15])
		flag_bit = data[18*i+15 : 18*i+16]
		//fmt.Println(name)
		if string(flag_bit) == "\x00" {
			name_flags := data[18*i+16 : 18*i+18]
			num, _ := Byte2Int(name_flags[0:1])
			if num >= 80 {
				group = strings.Trim(name, " ")
				//fmt.Printf("%s\t%s\t%s\n",name,"G",GROUP_NAMES[string(flag_bit)])
			} else {
				unique = name
				if string(flag_bit) == "\x20" {
					Share = true
				}
				//fmt.Printf("%s\t%s\t%s\n",name,"U",UNIQUE_NAMES[string(flag_bit)])
			}
		} else {
			if _, ok := GroupNames[string(flag_bit)]; ok {
				if string(flag_bit) == "\x1C" {
					DC = true
				}
			} else if _, ok := UniqueNames[string(flag_bit)]; ok {
				if string(flag_bit) == "\x20" {
					Share = true
				}
				//fmt.Printf("%s\t%s\t%s\n",name,"U",UNIQUE_NAMES[string(flag_bit)])
			}
		}
	}

	msg := group + "\\" + unique
	msg = strings.Replace(msg, "\x00", "", -1)
	result.Status = ""
	if Share {
		result.Status += "sharing"
	}
	if DC {
		result.Status += "DC"
	}
	result.Host = msg
	result.Protocol = "NetBIOS"
	return
}
