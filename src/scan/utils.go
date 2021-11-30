package scan

import (
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
