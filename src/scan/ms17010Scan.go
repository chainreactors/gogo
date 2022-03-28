package scan

import (
	"encoding/binary"
	. "getitle/src/fingers"
	. "getitle/src/pkg"
	"strings"
)

func ms17010Scan(result *Result) {
	var (
		negotiateProtocolRequest  = Decode("YmBgaP0f7OtUxMDAwCARfIABBfz/x8DgwMCQxMAU4Kzg5xoS7h/krRAQ5O8e5OirYKhnwMDk4+jn6+gHZoZn5qXklxcrpOUXKYTnF2WnF+WXFhQrGOsZJjIw+fga6hlFGBgYwbQY6RkyMPmFKPj4KhjoGRoxAAAAAP//")
		sessionSetupRequest       = Decode("YmBg6Pgf7OtUzMDAwCDBfoABBfz/x8DgwMD7n6GDgUWQCyrICKWvMDAweEOY4QyZDHkMKQz5DOUMxQwKDEYMBmAIYhkyWDKY4lVjyqDHYMDAwAAAAAD//w==")
		treeConnectRequest        = Decode("VMWxCQIxAADAEwQzggNYCwlEY6VoZSEItimyhPv9ZJ/n0/01h9Z/n+cfjofJRp+Fh33XBDuZqopukrPoooyv8jgpqrevlxPuKwsAAAD//w==")
		transNamedPipeRequest     = Decode("YmBg8Pof7OukysDAwCDBqMGADDj6FjNyBM0QALH/////H1nOC4yZGJQZGBjYGWICPANcYxgAAAAA//8=")
		trans2SessionSetupRequest = Decode("YmBg8Psf7OtkxMDAwCDBfoABGXD8/8fA4cjAz8PAwMAIFVt2cwkDAwMPgxNIJwMjAx8DL4oeBgAAAAD//w==")
	)
	// connecting to a host in LAN if reachable should be very quick
	result.Port = "445"
	target := result.GetTarget()
	conn, err := TcpSocketConn(target, RunOpt.Delay)
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Protocol = "smb"
	result.Open = true
	defer conn.Close()
	_, err = conn.Write(negotiateProtocolRequest)
	reply := make([]byte, 1024)
	// let alone half packet
	if n, err := conn.Read(reply); err != nil || n < 36 {
		result.Error = err.Error()
		return
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		return
	}

	_, _ = conn.Write(sessionSetupRequest)

	n, err := conn.Read(reply)
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
	// TODO change the target in tree path though it doesn't matter
	_, _ = conn.Write(treeConnectRequest)

	if n, err := conn.Read(reply); err != nil || n < 36 {
		result.Error = err.Error()
		return
	}

	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	_, _ = conn.Write(transNamedPipeRequest)
	if n, err := conn.Read(reply); err != nil || n < 36 {
		result.Error = err.Error()
		return
	}
	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		result.Title = strings.Replace(os, "\x00", "", -1)
		result.AddVuln(&Vuln{Name: "MS17-010"})

		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		_, _ = conn.Write(trans2SessionSetupRequest)

		if n, err := conn.Read(reply); err != nil || n < 36 {
			return
		}
		if reply[34] == 0x51 {
			result.AddVuln(&Vuln{Name: "DOUBLEPULSAR"})
		}
	}

	return
}
