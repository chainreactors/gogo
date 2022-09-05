package utils

import (
	"reflect"
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

func Unique(data interface{}) interface{} {
	inArr := reflect.ValueOf(data)
	if inArr.Kind() != reflect.Slice && inArr.Kind() != reflect.Array {
		return data
	}

	existMap := make(map[interface{}]bool)
	outArr := reflect.MakeSlice(inArr.Type(), 0, inArr.Len())

	for i := 0; i < inArr.Len(); i++ {
		iVal := inArr.Index(i)

		if _, ok := existMap[iVal.Interface()]; !ok {
			outArr = reflect.Append(outArr, inArr.Index(i))
			existMap[iVal.Interface()] = true
		}
	}

	return outArr.Interface()
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
