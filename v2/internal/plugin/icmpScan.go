package plugin

//Ladon Scanner for golang
//Author: k8gege
//K8Blog: http://k8gege.org/Ladon
//Github: https://github.com/k8gege/LadonGo

import (
	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"net"
	"time"
)

// -n i
func icmpScan(result *pkg.Result) {
	var size int
	var seq int16 = 1
	const EchoRequestHeadLen = 8
	host := result.Ip
	size = 32
	delay := time.Duration(RunOpt.Delay)
	conn, err := net.DialTimeout("ip4:icmp", host, delay*time.Second)
	if err != nil {
		result.ErrStat = 7
		result.Error = err.Error()
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(delay * time.Second)) // icmp 超时
	id0, id1 := genidentifier(host)

	var msg []byte = make([]byte, size+EchoRequestHeadLen)
	msg[0] = 8                        // echo
	msg[1] = 0                        // code 0
	msg[2] = 0                        // checksum
	msg[3] = 0                        // checksum
	msg[4], msg[5] = id0, id1         //identifier[0] identifier[1]
	msg[6], msg[7] = gensequence(seq) //sequence[0], sequence[1]
	length := size + EchoRequestHeadLen
	check := checkSum(msg[0:length])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)

	logs.Log.Debug("request icmp " + result.GetTarget())
	_, err = conn.Write(msg[0:length])
	if err != nil {
		result.Error = err.Error()
		return
	}

	const ECHO_REPLY_HEAD_LEN = 20
	var receive []byte = make([]byte, ECHO_REPLY_HEAD_LEN+length)
	n, err := conn.Read(receive)
	if err != nil {
		result.Error = err.Error()
		return
	}

	logs.Log.Debugf("[debug] %q", receive[:n])
	if receive[ECHO_REPLY_HEAD_LEN+4] != msg[4] || receive[ECHO_REPLY_HEAD_LEN+5] != msg[5] || receive[ECHO_REPLY_HEAD_LEN+6] != msg[6] || receive[ECHO_REPLY_HEAD_LEN+7] != msg[7] || receive[ECHO_REPLY_HEAD_LEN] == 11 {
		return
	}

	result.Open = true
	result.Protocol = "icmp"
	result.Status = "icmp"
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

func genidentifier(host string) (byte, byte) {
	return host[0], host[1]
}
