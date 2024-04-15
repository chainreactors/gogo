package plugin

import (
	"encoding/binary"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/logs"
	"strings"

	. "github.com/chainreactors/gogo/v2/pkg"
)

var (
	negotiateProtocolRequest  = Decode("YmBgaP0f7OtUxMDAwCARfIABBfz/x8DgwMCQxMAU4Kzg5xoS7h/krRAQ5O8e5OirYKhnwMDk4+jn6+gHZoZn5qXklxcrpOUXKYTnF2WnF+WXFhQrGOsZJjIw+fga6hlFGBgYwbQY6RkyMPmFKPj4KhjoGRoxAAAAAP//")
	sessionSetupRequest       = Decode("YmBg6Pgf7OtUzMDAwCDBfoABBfz/x8DgwMD7n6GDgUWQCyrICKWvMDAweEOY4QyZDHkMKQz5DOUMxQwKDEYMBmAIYhkyWDKY4lVjyqDHYMDAwAAAAAD//w==")
	treeConnectRequest        = Decode("VMWxCQIxAADAEwQzggNYCwlEY6VoZSEItimyhPv9ZJ/n0/01h9Z/n+cfjofJRp+Fh33XBDuZqopukrPoooyv8jgpqrevlxPuKwsAAAD//w==")
	transNamedPipeRequest     = Decode("YmBg8Pof7OukysDAwCDBqMGADDj6FjNyBM0QALH/////H1nOC4yZGJQZGBjYGWICPANcYxgAAAAA//8=")
	trans2SessionSetupRequest = Decode("YmBg8Psf7OtkxMDAwCDBfoABGXD8/8fA4cjAz8PAwMAIFVt2cwkDAwMPgxNIJwMjAx8DL4oeBgAAAAD//w==")
)

func ms17010Scan(result *Result) {
	if RunOpt.Opsec {
		logs.Log.Debugf("opsec!!! skip MS-17010 plugin")
		return
	}
	// connecting to a host in LAN if reachable should be very quick
	result.Port = "445"
	target := result.GetTarget()
	conn, err := NewSocket("tcp", target, RunOpt.Delay)
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Protocol = "smb"
	result.Open = true
	defer conn.Close()

	reply, err := conn.Request(negotiateProtocolRequest, 1024)
	n := len(reply)
	//reply := make([]byte, 1024)
	// let alone half packet
	if err != nil || len(reply) < 36 {
		result.Error = err.Error()
		return
	}
	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		return
	}

	reply, err = conn.Request(sessionSetupRequest, 1024)
	n = len(reply)
	//_, _ = conn.Write(sessionSetupRequest)
	//n, err := conn.Read(reply)
	if err != nil || n < 36 {
		result.Error = err.Error()
		return
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		return
	}

	// extract OS info
	var os string
	sessionSetupResponse := reply[36:n]
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		// find byte count
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount)+45 {
		} else {
			// two continous null bytes indicates end of a unicode string
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					os = string(sessionSetupResponse[10:i])
					break
				}
			}
		}
	}

	userID := reply[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]

	reply, err = conn.Request(treeConnectRequest, 1024)
	n = len(reply)
	if err != nil || n < 36 {
		result.Error = err.Error()
		return
	}

	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	reply, err = conn.Request(transNamedPipeRequest, 1024)
	n = len(reply)
	if err != nil || n < 36 {
		result.Error = err.Error()
		return
	}

	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		result.Title = strings.Replace(os, "\x00", "", -1)
		result.AddVuln(&common.Vuln{Name: "MS17-010", SeverityLevel: common.SeverityCRITICAL})

		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		reply, err = conn.Request(transNamedPipeRequest, 1024)
		n = len(reply)
		if err != nil || n < 36 {
			return
		}
		if reply[34] == 0x51 {
			result.AddVuln(&common.Vuln{Name: "DOUBLEPULSAR", SeverityLevel: common.SeverityCRITICAL})
		}
	}
	return
}
