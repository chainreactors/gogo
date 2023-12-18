package fingers

import (
	"github.com/chainreactors/utils/encode"
	"regexp"
	"strings"

	"github.com/chainreactors/parsers"
)

func compileRegexp(s string) (*regexp.Regexp, error) {
	reg, err := regexp.Compile(s)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

func compiledMatch(reg *regexp.Regexp, s []byte) (string, bool) {
	matched := reg.FindSubmatch(s)
	if matched == nil {
		return "", false
	}
	if len(matched) == 1 {
		return "", true
	} else {
		return strings.TrimSpace(string(matched[1])), true
	}
}

func compiledAllMatch(reg *regexp.Regexp, s string) ([]string, bool) {
	matchedes := reg.FindAllString(s, -1)
	if matchedes == nil {
		return nil, false
	}
	return matchedes, true
}

func FingerMatcher(finger *Finger, content map[string]interface{}, level int, sender func([]byte) ([]byte, bool)) (*parsers.Framework, *parsers.Vuln, bool) {
	return finger.Match(content, level, sender)
}

func RuleMatcher(rule *Rule, content map[string]interface{}, ishttp bool) (bool, bool, string) {
	var hasFrame, hasVuln bool
	var version string
	if rule.Regexps == nil {
		return false, false, ""
	}

	hasFrame, hasVuln, version = rule.Match(content["content"].([]byte), ishttp)
	if hasFrame || !ishttp {
		return hasFrame, hasVuln, version
	}

	if content["cert"] != nil {
		hasFrame = rule.MatchCert(content["cert"].(string))
	}

	return hasFrame, hasVuln, version
}

func FaviconMatch(content map[string]string) (*parsers.Framework, bool) {
	var frame *parsers.Framework
	if Md5Fingers[content["md5"]] != "" {
		frame = &parsers.Framework{Name: Md5Fingers[content["md5"]], From: parsers.FrameFromICO}
		return frame, true
	}

	if Mmh3Fingers[content["mmh3"]] != "" {
		frame = &parsers.Framework{Name: Mmh3Fingers[content["mmh3"]], From: parsers.FrameFromICO}
		return frame, true
	}
	return nil, false
}

func FaviconActiveMatch(favicon *Favicons, level int, sender func(string) ([]byte, bool)) (*parsers.Framework, bool) {
	if level > 1 && sender != nil && favicon.Path != "" {
		body, ok := sender(favicon.Path)
		if ok {
			content := map[string]string{
				"md5":  encode.Md5Hash(body),
				"mmh3": encode.Mmh3Hash32(body),
			}
			frame, ok := FaviconMatch(content)
			if ok {
				return frame, true
			}
		}
	}
	return nil, false
}
