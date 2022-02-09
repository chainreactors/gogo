package utils

import (
	"strings"
)

func SliceContains(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

//切片去重
func SliceUnique(ss []string) []string {
	res := make([]string, 0, len(ss))
	temp := map[string]struct{}{}
	for _, item := range ss {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			res = append(res, item)
		}
	}
	return res
}

func Str2uintlist(s string) []uint {
	var ipps []uint
	ss := strings.Split(s, ",")
	for _, ipp := range ss {
		ipps = append(ipps, uint(ToInt(ipp)))
	}
	return ipps
}

func UintSlice2str(i []uint) []string {
	s := make([]string, len(i))
	for k, v := range i {
		s[k] = ToString(v)
	}
	return s
}
