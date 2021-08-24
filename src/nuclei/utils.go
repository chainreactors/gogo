package nuclei

import (
	"fmt"
	"strconv"
	"strings"
)

// mergeMaps merges two maps into a New map
func mergeMaps(m1, m2 map[string]interface{}) map[string]interface{} {
	m := make(map[string]interface{}, len(m1)+len(m2))
	for k, v := range m1 {
		m[k] = v
	}
	for k, v := range m2 {
		m[k] = v
	}
	return m
}

const (
	markerGeneral          = "§"
	markerParenthesisOpen  = "{{"
	markerParenthesisClose = "}}"
)

// replace replaces placeholders in template with values on the fly.
func replace(template string, values map[string]interface{}) string {
	var replacerItems []string

	builder := &strings.Builder{}
	for key, val := range values {
		builder.WriteString(markerParenthesisOpen)
		builder.WriteString(key)
		builder.WriteString(markerParenthesisClose)
		replacerItems = append(replacerItems, builder.String())
		builder.Reset()
		replacerItems = append(replacerItems, toString(val))

		builder.WriteString(markerGeneral)
		builder.WriteString(key)
		builder.WriteString(markerGeneral)
		replacerItems = append(replacerItems, builder.String())
		builder.Reset()
		replacerItems = append(replacerItems, toString(val))
	}
	replacer := strings.NewReplacer(replacerItems...)
	final := replacer.Replace(template)
	return final
}

//func ReplaceRawRequest(rawrequest rawRequest, values map[string]interface{}) rawRequest {
//	rawrequest.Data = replace(rawrequest.Data, values)
//	rawrequest.FullURL = replace(rawrequest.FullURL, values)
//	for k, v := range rawrequest.Headers {
//		rawrequest.Headers[k] = replace(v, values)
//	}
//	return rawrequest
//}

// toString converts an interface to string in a quick way
func toString(data interface{}) string {
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
