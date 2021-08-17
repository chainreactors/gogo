package scan

//Ladon Scanner for golang
//Author: k8gege
//K8Blog: http://k8gege.org/Ladon
//Github: https://github.com/k8gege/LadonGo

import (
	"getitle/src/utils"
	"net"
	"strings"
	"time"
)

// -n i
func icmpScan(host string, result *utils.Result) {
	var size int
	var seq int16 = 1
	const ECHO_REQUEST_HEAD_LEN = 8

	size = 32
	delay := time.Duration(1)
	host = strings.Split(host, ":")[0]
	conn, err := net.DialTimeout("ip4:icmp", host, delay*time.Second)
	if err != nil {
		result.Error = err.Error()
		return
	}
	defer conn.Close()
	id0, id1 := genidentifier(host)

	var msg []byte = make([]byte, size+ECHO_REQUEST_HEAD_LEN)
	msg[0] = 8                        // echo
	msg[1] = 0                        // code 0
	msg[2] = 0                        // checksum
	msg[3] = 0                        // checksum
	msg[4], msg[5] = id0, id1         //identifier[0] identifier[1]
	msg[6], msg[7] = gensequence(seq) //sequence[0], sequence[1]

	length := size + ECHO_REQUEST_HEAD_LEN

	check := checkSum(msg[0:length])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)

	conn.SetDeadline(time.Now().Add(delay * time.Second))
	_, err = conn.Write(msg[0:length])

	const ECHO_REPLY_HEAD_LEN = 20

	var receive []byte = make([]byte, ECHO_REPLY_HEAD_LEN+length)
	_, err = conn.Read(receive)

	if err != nil || receive[ECHO_REPLY_HEAD_LEN+4] != msg[4] || receive[ECHO_REPLY_HEAD_LEN+5] != msg[5] || receive[ECHO_REPLY_HEAD_LEN+6] != msg[6] || receive[ECHO_REPLY_HEAD_LEN+7] != msg[7] || receive[ECHO_REPLY_HEAD_LEN] == 11 {
		//result.Error = err.Error()
		return
	} else {
		result.Stat = "OPEN"
		result.Protocol = "icmp"
		result.HttpStat = "icmp"
	}
	return
}

//func IcmpOK(host string)(isok bool) {
//	var size int
//	var seq int16 = 1
//	const ECHO_REQUEST_HEAD_LEN = 8
//
//	size = 32
//
//	conn, err := net.DialTimeout("ip4:icmp", host, Delay*time.Second)
//	if err != nil {
//		return false
//	}
//	defer conn.Close()
//	id0, id1 := genidentifier(host)
//
//	var msg []byte = make([]byte, size+ECHO_REQUEST_HEAD_LEN)
//	msg[0] = 8                        // echo
//	msg[1] = 0                        // code 0
//	msg[2] = 0                        // checksum
//	msg[3] = 0                        // checksum
//	msg[4], msg[5] = id0, id1         //identifier[0] identifier[1]
//	msg[6], msg[7] = gensequence(seq) //sequence[0], sequence[1]
//
//	length := size + ECHO_REQUEST_HEAD_LEN
//
//	check := checkSum(msg[0:length])
//	msg[2] = byte(check >> 8)
//	msg[3] = byte(check & 255)
//
//	conn.SetDeadline(time.Now().Add(Delay * time.Second))
//	_, err = conn.Write(msg[0:length])
//
//	const ECHO_REPLY_HEAD_LEN = 20
//
//	var receive []byte = make([]byte, ECHO_REPLY_HEAD_LEN+length)
//	n, err := conn.Read(receive)
//	_ = n
//
//	if err != nil || receive[ECHO_REPLY_HEAD_LEN+4] != msg[4] || receive[ECHO_REPLY_HEAD_LEN+5] != msg[5] || receive[ECHO_REPLY_HEAD_LEN+6] != msg[6] || receive[ECHO_REPLY_HEAD_LEN+7] != msg[7]  || receive[ECHO_REPLY_HEAD_LEN] == 11 {
//		//
//	} else {
//		return true
//	}
//
//	return isok
//}

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
	sum += (sum >> 16)
	var answer uint16 = uint16(^sum)
	return answer
}

//func checkError(err error) {
//	if err != nil {
//		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
//		os.Exit(1)
//	}
//}

func gensequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}

func genidentifier(host string) (byte, byte) {
	return host[0], host[1]
}
