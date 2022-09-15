package fingers

import (
	"regexp"
	"strings"
)

func compiledMatch(reg *regexp.Regexp, s string) (string, bool) {
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

func FingerMatcher(finger *Finger, content string, level int, sender func([]byte) (string, bool)) (*Framework, *Vuln, bool) {
	return finger.Match(content, level, sender)
}

func RuleMatcher(rule *Rule, content string, ishttp bool) (bool, bool, string) {
	return rule.Match(content, ishttp)
}
