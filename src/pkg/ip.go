package pkg

import (
	"net"
	"sort"
	"strings"
)

func IsIPv4(ip string) bool {
	address := net.ParseIP(ip).To4()
	if address != nil {
		return true
	}
	return false
}

func ParseIP(target string) string {
	target = strings.TrimSpace(target)
	if IsIPv4(target) {
		return target
	}
	iprecords, err := net.LookupIP(target)
	if err != nil {
		Log.Error("Unable to resolve domain name:" + target + ". SKIPPED!")
		return ""
	}
	for _, ip := range iprecords {
		if ip.To4() != nil {
			Log.Important("parse domain SUCCESS, map " + target + " to " + ip.String())
			return ip.String()
		}
	}
	return ""
}

func Ip2Int(ip string) uint {
	s2ip := net.ParseIP(ip).To4()
	return uint(s2ip[3]) | uint(s2ip[2])<<8 | uint(s2ip[1])<<16 | uint(s2ip[0])<<24
}

func Int2Ip(ipint uint) string {
	ip := make(net.IP, net.IPv4len)
	ip[0] = byte(ipint >> 24)
	ip[1] = byte(ipint >> 16)
	ip[2] = byte(ipint >> 8)
	ip[3] = byte(ipint)
	return ip.String()
}

func sortIP(ips []string) []string {
	sort.Slice(ips, func(i, j int) bool {
		return Ip2Int(ips[i]) < Ip2Int(ips[j])
	})
	return ips
}
