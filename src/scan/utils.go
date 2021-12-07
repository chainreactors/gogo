package scan

import (
	"fmt"
	"getitle/src/structutils"
	"github.com/JKme/go-ntlmssp"
	"strings"
)

var windowsVer = map[string]string{
	"5.0.2195": "2000",
	"5.1.2600": "XP",
	//"5.1.2600.1105": "XP SP1",
	//"5.1.2600.1106": "XP SP1",
	//"5.1.2600.2180": "XP SP2",
	"5.2.3790": "Server 2003/Server 2003 R2",
	//"5.2.3790.1180": "Server 2003 SP1",
	"6.0.6000":   "Vista",
	"6.0.6001":   "Vista SP1/Server2008",
	"6.0.6002":   "Vista SP2/Server2008 SP2",
	"6.1.0":      "7/Server2008 R2",
	"6.1.7600":   "7/Server2008 R2",
	"6.1.7601":   "7 SP1/Server2008 R2 SP1",
	"6.2.9200":   "8/Server2012",
	"6.3.9600":   "8.1/Server2012 R2",
	"10.0.10240": "10 1507",
	"10.0.10586": "10 1511",
	"10.0.14393": "10 1607/Server2016",
	"10.0.15063": "10 1703",
	"10.0.16299": "10 1709",
	"10.0.17134": "10 1803",
	"10.0.17763": "10 1809/Server2019",
	"10.0.18362": "10 1903",
	"10.0.18363": "10 1909",
	"10.0.19041": "10 2004/Server2004",
	"10.0.19042": "10 20H2/Server20H2",
	"10.0.19043": "10 21H2",
	"10.0.20348": "Server2022",
	"11.0.22000": "11",
}

func trimName(name string) string {
	return strings.TrimSpace(strings.Replace(name, "\x00", "", -1))
}

func bytes2Uint(bs []byte, endian byte) uint64 {
	var u uint64
	if endian == '>' {
		for i := 0; i < len(bs); i++ {
			u += uint64(bs[i]) << uint(8*(len(bs)-i-1))
		}
	} else {
		for i := 0; i < len(bs); i++ {
			u += uint64(bs[len(bs)-i-1]) << uint(8*(len(bs)-i-1))
		}
	}
	return u
}

func NTLMInfo(ret []byte) map[string]string {
	flags := ntlmssp.NewChallengeMsg(ret)
	tinfo := ntlmssp.ParseAVPair(flags.TargetInfo())
	delete(tinfo, "MsvAvTimestamp")
	offset_version := 48
	version := ret[offset_version : offset_version+8]
	ver, _ := ntlmssp.ReadVersionStruct(version)
	build := fmt.Sprintf("%d.%d.%d", ver.ProductMajorVersion, ver.ProductMinorVersion, ver.ProductBuild)
	tinfo["Version"] = fmt.Sprintf("Windows %s_(%s)", windowsVer[build], build)
	return structutils.ToStringMap(tinfo)
}
