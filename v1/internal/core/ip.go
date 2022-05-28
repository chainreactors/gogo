package core

import (
	. "getitle/v1/pkg"
	"math"
	"net"
	"sort"
)

func mask2ipuint(mask int) uint64 {
	return ((uint64(4294967296) >> uint(32-mask)) - 1) << uint(32-mask)
}

func ip2superip(ip string, mask int) string {
	ipint := Ip2Int(ip)
	return Int2Ip(ipint & uint(mask2ipuint(mask)))
}

func getMask(cidr string) int {
	_, mask := SplitCIDR(cidr)
	return mask
}

func getIP(cidr string) string {
	ip, _ := SplitCIDR(cidr)
	return ip
}

func getMaskRange(mask int) (before uint, after uint) {
	before = uint(math.Pow(2, 32) - math.Pow(2, float64(32-mask)))
	after = uint(math.Pow(2, float64(32-mask)) - 1)
	return before, after
}

func getIpRange(target string) (start uint, fin uint) {
	_, cidr, err := net.ParseCIDR(target)
	if err != nil {
		return 0, 0
	}
	mask, _ := cidr.Mask.Size()
	before, after := getMaskRange(mask)
	ipint := Ip2Int(cidr.IP.String())

	start = ipint & before
	fin = ipint | after
	return start, fin
}

func sortCIDR(cidrs []string) []string {
	sort.Slice(cidrs, func(i, j int) bool {
		ip_i, _ := SplitCIDR(cidrs[i])
		ip_j, _ := SplitCIDR(cidrs[j])
		return Ip2Int(ip_i) < Ip2Int(ip_j)
	})
	return cidrs
}
