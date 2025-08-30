package engine

//Ladon Scanner for golang
//Author: k8gege
//K8Blog: http://k8gege.org/Ladon
//Github: https://github.com/k8gege/LadonGo

import (
	"net"
	"time"

	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
)

const (
	echoRequestHeadLen = 8
	echoReplyHeadLen   = 20
	icmpDataLen        = 32
)

var (
	icmpData         = []byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69}
	icmpSEQ    int16 = 1
	icmpStatus       = map[uint8]string{
		0:  "pong",
		3:  "unreachable",
		4:  "quench",
		5:  "redirect",
		8:  "ping",
		9:  "advertisement",
		10: "solicitation",
		11: "timeout",
	}
)

func getICMPStatus(t uint8) string {
	if icmpStatus[t] != "" {
		return icmpStatus[t]
	}
	return "unknown"
}

func ICMPScan(opt *pkg.RunnerOption, result *pkg.Result) {
	host := result.Ip
	delay := time.Duration(opt.Delay)
	conn, err := net.DialTimeout("ip4:icmp", host, delay*time.Second)
	if err != nil {
		result.ErrStat = 7
		result.Error = err.Error()
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(delay * time.Second)) // icmp 超时

	var msg []byte = make([]byte, icmpDataLen+echoRequestHeadLen)
	msg[0] = 8                            // echo
	msg[1] = 0                            // code 0
	msg[2] = 0                            // checksum
	msg[3] = 0                            // checksum
	msg[4], msg[5] = 0, 1                 //identifier[0] identifier[1]
	msg[6], msg[7] = gensequence(icmpSEQ) //sequence[0], sequence[1]
	icmpSEQ++
	length := icmpDataLen + echoRequestHeadLen
	copy(msg[8:], icmpData)
	check := checkSum(msg[0:length])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)

	logs.Log.Debug("request icmp " + result.GetTarget())
	result.ErrStat = 7
	_, err = conn.Write(msg[0:length])
	if err != nil {
		result.Error = err.Error()
		return
	}

	var receive []byte = make([]byte, echoReplyHeadLen+length)
	n, err := conn.Read(receive)
	if err != nil {
		result.Error = err.Error()
		return
	}

	logs.Log.Debugf(" %q", receive[:n])
	if receive[echoReplyHeadLen+4] != msg[4] || receive[echoReplyHeadLen+5] != msg[5] || receive[echoReplyHeadLen+6] != msg[6] || receive[echoReplyHeadLen+7] != msg[7] || receive[echoReplyHeadLen] == 11 {
		return
	}

	result.Open = true
	result.Protocol = "icmp"
	result.Status = getICMPStatus(receive[echoReplyHeadLen])
	return
}

func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256 // notice here, why *256?
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	var answer uint16 = uint16(^sum)
	return answer
}

func gensequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}
