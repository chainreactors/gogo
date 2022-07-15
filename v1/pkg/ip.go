package pkg

import (
	"getitle/v1/pkg/utils"
	. "github.com/chainreactors/logs"
	"net"
	"net/url"
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

func ParseIP(target string) (string, bool) {
	target = strings.TrimSpace(target)
	if IsIPv4(target) {
		return target, false
	}
	iprecords, err := net.LookupIP(target)
	if err != nil {
		Log.Error("Unable to resolve domain name:" + target + ". SKIPPED!")
		return "", false
	}
	for _, ip := range iprecords {
		if ip.To4() != nil {
			Log.Important("parse domain SUCCESS, map " + target + " to " + ip.String())
			return ip.String(), true
		}
	}
	return "", false
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

func ParseHost(target string) string {
	if strings.Contains(target, "http") {
		u, err := url.Parse(target)
		if err != nil {
			Log.Error(err.Error())
			return ""
		}
		return u.Hostname()
	} else {
		return strings.TrimSpace(strings.Trim(target, "/"))
	}
}

func ParseCIDR(target string) (string, string) {
	// return ip, hosts
	var ip, mask string
	target = strings.TrimSpace(target)
	target = ParseHost(target)
	if strings.Contains(target, "/") {
		ip = strings.Split(target, "/")[0]
		mask = strings.Split(target, "/")[1]
		if !(utils.ToInt(mask) > 0 && utils.ToInt(mask) <= 32) {
			Log.Warn(target + " netmask out of 1-32")
			mask = "32"
		}
	} else {
		ip = target
		mask = "32"
	}

	if parsedIp, isparse := ParseIP(ip); parsedIp != "" {
		if isparse {
			return parsedIp + "/" + mask, ip
		} else {
			return parsedIp + "/" + mask, ""
		}
	} else {
		return "", ""
	}
}

func SplitCIDR(cidr string) (string, int) {
	tmp := strings.Split(cidr, "/")
	if len(tmp) == 2 {
		return tmp[0], utils.ToInt(tmp[1])
	} else {
		return tmp[0], 32
	}
}
