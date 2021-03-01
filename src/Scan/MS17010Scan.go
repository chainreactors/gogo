package Scan

import (
	"encoding/binary"
	"encoding/hex"
	"getitle/src/Utils"
)

var (
	negotiateProtocolRequest, _  = hex.DecodeString("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
	sessionSetupRequest, _       = hex.DecodeString("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
	treeConnectRequest, _        = hex.DecodeString("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
	transNamedPipeRequest, _     = hex.DecodeString("0000004aff534d42250000000018012800000000000000000000000000088ea3010852981000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
	trans2SessionSetupRequest, _ = hex.DecodeString("0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")
)

func MS17010Scan(target string, result *Utils.Result) *Utils.Result {
	// connecting to a host in LAN if reachable should be very quick
	result.Protocol = "SMB"
	conn, err := Utils.TcpSocketConn(target, Delay)
	if err != nil {

		//fmt.Println(err)
		result.Error = err.Error()
		return result
	}
	result.Stat = "OPEN"
	defer conn.Close()
	_, err = conn.Write(negotiateProtocolRequest)
	reply := make([]byte, 1024)
	// let alone half packet
	if n, err := conn.Read(reply); err != nil || n < 36 {
		result.Error = err.Error()
		return result
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		return result
	}

	_, _ = conn.Write(sessionSetupRequest)

	n, err := conn.Read(reply)
	if err != nil || n < 36 {
		result.Error = err.Error()
		return result
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		return result
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
		return result
	}

	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	_, _ = conn.Write(transNamedPipeRequest)
	if n, err := conn.Read(reply); err != nil || n < 36 {
		result.Error = err.Error()
		conn.Close()
		return result
	}

	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		result.Title = os
		result.HttpStat = "SMB"
		result.Vuln = "MS17010"
		// detect present of DOUBLEPULSAR SMB implant
	}
	conn.Close()
	return result
}
