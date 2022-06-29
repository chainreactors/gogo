package dsl

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"getitle/v1/pkg/utils"
	"github.com/twmb/murmur3"
)

func Base64Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		utils.Fatal("" + err.Error())
	}
	return data
}

func Base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func UnHexlify(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		utils.Fatal("" + err.Error())
	}
	return b
}

func Hexlify(b []byte) string {
	return hex.EncodeToString(b)
}

func Md5Hash(raw []byte) string {
	m := md5.Sum(raw)
	return hex.EncodeToString(m[:])
}

func Mmh3Hash32(raw []byte) string {
	var h32 = murmur3.New32()
	_, _ = h32.Write(standBase64(raw))
	return fmt.Sprintf("%d", h32.Sum32())
}

func standBase64(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}
