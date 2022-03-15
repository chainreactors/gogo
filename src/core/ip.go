package core

import (
	. "getitle/src/pkg"
	. "getitle/src/utils"
	"math"
	"net"
	"net/url"
	"sort"
	"strings"
)

func mask2ipuint(mask int) uint64 {
	return ((uint64(4294967296) >> uint(32-mask)) - 1) << uint(32-mask)
}

func ip2superip(ip string, mask int) string {
	ipint := Ip2Int(ip)
	return Int2Ip(ipint & uint(mask2ipuint(mask)))
}

func splitCIDR(cidr string) (string, int) {
	tmp := strings.Split(cidr, "/")
	if len(tmp) == 2 {
		return tmp[0], ToInt(tmp[1])
	} else {
		return tmp[0], 32
	}
}

func getMask(cidr string) int {
	_, mask := splitCIDR(cidr)
	return mask
}

func getIP(cidr string) string {
	ip, _ := splitCIDR(cidr)
	return ip
}

func getMaskRange(mask int) (before uint, after uint) {
	before = uint(math.Pow(2, 32) - math.Pow(2, float64(32-mask)))
	after = uint(math.Pow(2, float64(32-mask)) - 1)
	return before, after
}

func getIpRange(target string) (start uint, fin uint) {
	_, cidr, _ := net.ParseCIDR(target)
	mask, _ := cidr.Mask.Size()
	before, after := getMaskRange(mask)
	ipint := Ip2Int(cidr.IP.String())

	start = ipint & before
	fin = ipint | after
	return start, fin
}

func cidrFormat(target string) (string, string) {
	// return ip, host
	var ip, mask string
	target = strings.TrimSpace(target)
	if strings.Contains(target, "http") {
		u, err := url.Parse(target)
		if err != nil {
			Log.Error(err.Error())
			return "", ""
		}
		target = u.Hostname()
	}

	target = strings.Trim(target, "/")
	if strings.Contains(target, "/") {
		ip = strings.Split(target, "/")[0]
		mask = strings.Split(target, "/")[1]
	} else {
		ip = target
		mask = "32"
	}

	if parsedIp, isparse := ParseIP(ip); ip != "" {
		if isparse {
			return parsedIp + "/" + mask, ip
		} else {
			return parsedIp + "/" + mask, ""
		}
	} else {
		return "", ""
	}
}

func initIP(config *Config) {
	config.HostsMap = make(map[string]string)
	// 优先处理ip
	if config.IP != "" {
		if strings.Contains(config.IP, ",") {
			config.IPlist = strings.Split(config.IP, ",")
		} else {
			var host string
			config.IP, host = cidrFormat(config.IP)
			if host != "" {
				ip, _ := splitCIDR(config.IP)
				config.HostsMap[ip] = host
			}
			if config.IP == "" {
				Fatal("IP format error")
			}
		}
	}

	// 如果输入的是文件,则格式化所有输入值.如果无有效ip
	if config.IPlist != nil {
		var iplist []string
		for _, ip := range config.IPlist {
			ip, host := cidrFormat(ip)
			if host != "" {
				i, _ := splitCIDR(ip)
				config.HostsMap[i] = host
			}
			if ip != "" {
				iplist = append(iplist, ip)
			}
		}
		config.IPlist = SliceUnique(iplist) // 去重
		if len(config.IPlist) == 0 {
			Fatal("all targets format error")
		}
	}
}

func sort_cidr(cidrs []string) []string {
	sort.Slice(cidrs, func(i, j int) bool {
		ip_i, _ := splitCIDR(cidrs[i])
		ip_j, _ := splitCIDR(cidrs[j])
		return Ip2Int(ip_i) < Ip2Int(ip_j)
	})
	return cidrs
}
