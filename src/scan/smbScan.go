package scan

// from https://github.com/JKme/cube/blob/cb84da1f305f1f6a92ae3011c7be9c0f998c3571/plugins/probe/ntlm_smb.go
import (
	"bytes"
	"encoding/hex"
	"errors"
	. "getitle/src/pkg"
	"getitle/src/utils"
	"github.com/M09ic/go-ntlmssp"
)

var v1d1 = Decode("YmBgaP0f7OtUxMDAwCARfIIBBfz/B6aSGJgCnBX8XEPC/YO8FQKC/N2DHH0VDPUMGJh8HP18Hf3AzPDMvJT88mKFtPwihfD8ouz0ovzSgmIFYz3DRAYmH19DPaMIAwMjmBYjPUMGJr8QBR9fBQM9QyMGAAAAAP//")
var v1d2 = Decode("jIwxS8NAHEffHclFjhBXxxvFgBwJEgQRdRIxEjjBVYkZgqBgoN3zSUI+Tad26edpSkOGtlPf8IY/7/8DoQeXPzUAF8GCA4YNPBAOaOE9JtPxZfQauhWfz0rFSvi+7O7tXRfZUOlYCU+0mZS6v/Iu395fc+cKBBC0Zz1H+HIZAed8UPPLN3/MaTA4Kv6ZjTYkWCwphpSMW+xeUVNSYSj4ouRnrHecunjD9fSxBQAA//8=")
var v2d1 = Decode("YmBgcP0f7OtUxMDAwCDB6MGABP7/X8MMZigxMPmFKPj4KhjoGRoxMAX7OikY6RkYwJn29vYMAAAAAP//")
var v2d2 = Decode("YmBgyPgX7OvkwMDIgA4wRbADFQYmsFoHPGqYmASYAAAAAP//")

func ntlmdata(Flags []byte) []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x9A, 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x58, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x60, 0x40, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05,
		0x05, 0x02, 0xA0, 0x36, 0x30, 0x34, 0xA0, 0x0E, 0x30, 0x0C,
		0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02,
		0x02, 0x0A, 0xA2, 0x22, 0x04, 0x20, 0x4E, 0x54, 0x4C, 0x4D,
		0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00,
		Flags[0], Flags[1],
		Flags[2], Flags[3],
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func smbScan(result *Result) {
	result.Port = "445"
	target := result.GetTarget()
	var err error
	var ret []byte
	//ff534d42 SMBv1的标示
	//fe534d42 SMBv2的标示
	//先发送探测SMBv1的payload，不支持的SMBv1的时候返回为空，然后尝试发送SMBv2的探测数据包
	//if hex.EncodeToString(r1[4:8]) == "ff534d42" {
	//ret, err = smb1Scan(target)
	ret, err = smb1Scan(target)
	if err != nil && err.Error() == "conn failed" {
		return
	}

	if ret == nil {
		result.Open = true
		if ret, err = smb2Scan(target); ret != nil {
			result.HttpStat = "SMB2"
		} else {
			result.Protocol = "tcp"
			result.HttpStat = "tcp"
			return
		}
	} else {
		result.Open = true
		result.HttpStat = "SMB1"
	}

	result.Protocol = "smb"
	result.AddNTLMInfo(utils.ToStringMap(ntlmssp.NTLMInfo(ret)), "smb")
}

func smb1Scan(target string) ([]byte, error) {
	var err error
	conn, err := TcpSocketConn(target, RunOpt.Delay)
	if err != nil {
		return nil, errors.New("conn failed")
	}
	defer conn.Close()
	_, err = SocketSend(conn, v1d1, 4096)
	if err != nil {
		return nil, err
	}

	r2, err := SocketSend(conn, v1d2, 4096)
	//if err != nil || len(r2) < 47 {
	//	return nil, err
	//}
	//gss_native := r2[47:]

	off_ntlm := bytes.Index(r2, []byte("NTLMSSP"))
	if off_ntlm != -1 {
		return r2[off_ntlm:], err
	}
	return nil, err
}

func smb2Scan(target string) ([]byte, error) {
	var err error
	conn, err := TcpSocketConn(target, RunOpt.Delay)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	r2, err := SocketSend(conn, v2d1, 4096)

	if err != nil {
		return nil, err
	}

	var NTLMSSPNegotiatev2Data []byte
	if hex.EncodeToString(r2[70:71]) == "03" {
		NTLMSSPNegotiatev2Data = ntlmdata([]byte{0x15, 0x82, 0x08, 0xa0})
	} else {
		NTLMSSPNegotiatev2Data = ntlmdata([]byte{0x05, 0x80, 0x08, 0xa0})
	}

	_, err = SocketSend(conn, v2d2, 4096)
	if err != nil {
		return nil, err
	}

	ret, _ := SocketSend(conn, NTLMSSPNegotiatev2Data, 4096)
	ntlmOff := bytes.Index(ret, []byte("NTLMSSP"))
	if ntlmOff != -1 {
		return ret[ntlmOff:], err
	} else {
		return nil, err
	}
}
