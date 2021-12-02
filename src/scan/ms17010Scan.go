package scan

import (
	"encoding/binary"
	. "getitle/src/structutils"
	"getitle/src/utils"
	"strings"
)

func ms17010Scan(result *utils.Result) {
	var (
		negotiateProtocolRequest = Unzip("H4sIAAAAAAAA/2JgYGj9H+zrVMTAwMAgEXyAAQX8/8fA4MDAkMTAFOCs4OcaEu4f5K0QEOTvHuToq2CoZ8DA5OPo5+voB2aGZ+al5JcXK6TlFymE5xdlpxfllxYUKxjrGSYyMPn4GuoZRRgYGMG0GOkZMjD5hSj4+CoY6BkaMQAAAAD//wEAAP//1eOKXIkAAAA=")
		sessionSetupRequest      = Unzip("H4sIAAAAAAAA/2JgYOj4H+zrVMzAwMAgwX6AAQX8/8fA4MDA+5+hg4FFkAsqyAilrzAwMHhDmOEMmQx5DCkM+QzlDMUMCgxGDAZgCGIZMlgymOJVY8qgx2DAwMAAAAAA//8BAAD//5V7xReMAAAA")
		treeConnectRequest       = Unzip("H4sIAAAAAAAA/1TFsQkCMQAAwBMEM4IDWAsJRGOlaGUhCLYpsoT7/WSf59P9NYfWf5/nH46HyUafhYd91wQ7maqKbpKz6KKMr/I4Kaq3r5cT7isLAAAA//8BAAD///L5u6lkAAAA")
		transNamedPipeRequest    = Unzip("H4sIAAAAAAAA/2JgYPD6H+zrpMrAwMAgwajBgAw4+hYzcgTNEACx/////x9ZzguMmRiUGRgY2BliAjwDXGMYAAAAAP//AQAA//+OaounTgAAAA==")
	)
	// connecting to a host in LAN if reachable should be very quick
	result.Port = "445"
	target := result.GetTarget()
	conn, err := utils.TcpSocketConn(target, Delay)
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
		result.AddVuln(utils.Vuln{Name: "MS17-010"})
		// detect present of DOUBLEPULSAR SMB implant
	}
	return
}
