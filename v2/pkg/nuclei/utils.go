package nuclei

import (
	"github.com/chainreactors/parsers/iutils"
	"strings"
)

const (
	markerGeneral          = "§"
	markerParenthesisOpen  = "{{"
	markerParenthesisClose = "}}"
)

// Replace replaces placeholders in template with values on the fly.
func Replace(template string, values map[string]interface{}) string {
	var replacerItems []string

	builder := &strings.Builder{}
	for key, val := range values {
		builder.WriteString(markerParenthesisOpen)
		builder.WriteString(key)
		builder.WriteString(markerParenthesisClose)
		replacerItems = append(replacerItems, builder.String())
		builder.Reset()
		replacerItems = append(replacerItems, iutils.ToString(val))

		builder.WriteString(markerGeneral)
		builder.WriteString(key)
		builder.WriteString(markerGeneral)
		replacerItems = append(replacerItems, builder.String())
		builder.Reset()
		replacerItems = append(replacerItems, iutils.ToString(val))
	}
	replacer := strings.NewReplacer(replacerItems...)
	final := replacer.Replace(template)
	return final
}

//func ReplaceRawRequest(rawrequest rawRequest, values map[string]interface{}) rawRequest {
//	rawrequest.Data = Replace(rawrequest.Data, values)
//	rawrequest.FullURL = Replace(rawrequest.FullURL, values)
//	for k, v := range rawrequest.Headers {
//		rawrequest.Headers[k] = Replace(v, values)
//	}
//	return rawrequest
//}
// MergeMaps merges two maps into a New map
