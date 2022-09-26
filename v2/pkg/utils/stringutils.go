package utils

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func ToString(data interface{}) string {
	switch s := data.(type) {
	case nil:
		return ""
	case string:
		return s
	case bool:
		return strconv.FormatBool(s)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(s), 'f', -1, 32)
	case int:
		return strconv.Itoa(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case int32:
		return strconv.Itoa(int(s))
	case int16:
		return strconv.FormatInt(int64(s), 10)
	case int8:
		return strconv.FormatInt(int64(s), 10)
	case uint:
		return strconv.FormatUint(uint64(s), 10)
	case uint64:
		return strconv.FormatUint(s, 10)
	case uint32:
		return strconv.FormatUint(uint64(s), 10)
	case uint16:
		return strconv.FormatUint(uint64(s), 10)
	case uint8:
		return strconv.FormatUint(uint64(s), 10)
	case []byte:
		return string(s)
	case fmt.Stringer:
		return s.String()
	case error:
		return s.Error()
	default:
		return fmt.Sprintf("%v", data)
	}
}

func ToInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}

func AsciiEncode(s string) string {
	s = strings.TrimSpace(s)
	s = fmt.Sprintf("%q", s)
	s = strings.Trim(s, "\"")
	return s
}

func Match(regexpstr string, s string) (string, bool) {
	reg, err := regexp.Compile(regexpstr)
	if err != nil {
		return "", false
	}
	res := reg.FindStringSubmatch(s)
	if len(res) == 1 {
		return "", true
	} else if len(res) == 2 {
		return res[1], true
	}
	return "", false
}

func CompiledMatch(reg *regexp.Regexp, s string) (string, bool) {
	matched := reg.FindStringSubmatch(s)
	if matched == nil {
		return "", false
	}
	if len(matched) == 1 {
		return "", true
	} else {
		return strings.TrimSpace(matched[1]), true
	}
}

func CompiledAllMatch(reg *regexp.Regexp, s string) ([]string, bool) {
	matchedes := reg.FindAllString(s, -1)
	if matchedes == nil {
		return nil, false
	}
	return matchedes, true
}
