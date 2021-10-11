package scan

import (
	"fmt"
	"getitle/src/structutils"
	"github.com/JKme/go-ntlmssp"
	"strings"
)

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
	type2 := ntlmssp.NewChallengeMsg(ret)
	tinfo := ntlmssp.ParseAVPair(type2.TargetInfo())
	delete(tinfo, "MsvAvTimestamp")
	res := make(map[string]string)
	offset_version := 48
	version := ret[offset_version : offset_version+8]
	ver, _ := ntlmssp.ReadVersionStruct(version)
	tinfo["Version"] = fmt.Sprintf("Windows %d.%d.%d", ver.ProductMajorVersion, ver.ProductMinorVersion, ver.ProductBuild)
	for k, v := range tinfo {
		res[k] = structutils.ToString(v)
	}
	return res
}
