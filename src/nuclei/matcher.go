package nuclei

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

type matcher struct {
	// Type is the type of the matcher
	Type string `json:"type"`
	// Condition is the optional condition between two matcher variables
	//
	// By default, the condition is assumed to be OR.
	Condition string `json:"condition,omitempty"`

	// Part is the part of the data to match
	Part string `json:"part,omitempty"`

	// Negative specifies if the match should be reversed
	// It will only match if the condition is not true.
	Negative bool `json:"negative,omitempty"`

	// Name is matcher Name
	Name string `json:"name,omitempty"`
	// Status are the acceptable status codes for the response
	Status []int `json:"status,omitempty"`
	// Size is the acceptable size for the response
	Size []int `json:"size,omitempty"`
	// Words are the words required to be present in the response
	Words []string `json:"words,omitempty"`
	// Regex are the regex pattern required to be present in the response
	Regex []string `json:"regex,omitempty"`
	// Binary are the binary characters required to be present in the response
	Binary []string `json:"binary,omitempty"`
	// DSL are the dsl queries
	DSL []string `json:"dsl,omitempty"`
	// Encoding specifies the encoding for the word content if any.
	Encoding string `json:"encoding,omitempty"`

	MatchersCondition string `json:"matchers-condition"`
	Matchers          []matcher
	condition         conditionType
	matcherType       matcherType
	regexCompiled     []*regexp.Regexp
}

// matcherType is the type of the matcher specified
type matcherType = int

const (
	// wordsMatcher matches responses with words
	wordsMatcher matcherType = iota + 1
	// regexMatcher matches responses with regexes
	regexMatcher
	// binaryMatcher matches responses with words
	binaryMatcher
	// statusMatcher matches responses with status codes
	statusMatcher
	// sizeMatcher matches responses with response size
	sizeMatcher
	// dSLMatcher matches based upon dsl syntax
	dSLMatcher
)

// matcherTypes is an table for conversion of matcher type from string.
var matcherTypes = map[string]matcherType{
	"status": statusMatcher,
	"size":   sizeMatcher,
	"word":   wordsMatcher,
	"regex":  regexMatcher,
	"binary": binaryMatcher,
	"dsl":    dSLMatcher,
}

// conditionType is the type of condition for matcher
type conditionType int

const (
	// andCondition matches responses with AND condition in arguments.
	andCondition conditionType = iota + 1
	// orCondition matches responses with AND condition in arguments.
	orCondition
)

// conditionTypes is an table for conversion of condition type from string.
var conditionTypes = map[string]conditionType{
	"and": andCondition,
	"or":  orCondition,
}

// Result reverts the results of the match if the matcher is of type negative.
func (m *matcher) result(data bool) bool {
	if m.Negative {
		return !data
	}
	return data
}

// getType returns the type of the matcher
func (m *matcher) getType() matcherType {
	return m.matcherType
}

// CompileMatchers performs the initial setup operation on a matcher
func (m *matcher) CompileMatchers() error {
	var ok bool

	// Support hexadecimal encoding for matchers too.
	if m.Encoding == "hex" {
		for i, word := range m.Words {
			if decoded, err := hex.DecodeString(word); err == nil && len(decoded) > 0 {
				m.Words[i] = string(decoded)
			}
		}
	}

	// Setup the matcher type
	m.matcherType, ok = matcherTypes[m.Type]
	if !ok {
		return fmt.Errorf("unknown matcher type specified: %s", m.Type)
	}
	// By default, match on body if user hasn't provided any specific items
	if m.Part == "" {
		m.Part = "body"
	}

	// Compile the regexes
	for _, regex := range m.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		m.regexCompiled = append(m.regexCompiled, compiled)
	}

	// Compile the dsl expressions
	// todo dsl错误处理

	// Setup the condition type, if any.
	if m.Condition != "" {
		m.condition, ok = conditionTypes[m.Condition]
		if !ok {
			return fmt.Errorf("unknown condition specified: %s", m.Condition)
		}
	} else {
		m.condition = orCondition
	}
	return nil
}

// matchStatusCode matches a status code check against a corpus
func (m *matcher) matchStatusCode(statusCode int) bool {
	// Iterate over all the status codes accepted as valid
	//
	// Status codes don't support AND conditions.
	for _, status := range m.Status {
		// Continue if the status codes don't match
		if statusCode != status {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}

// matchSize matches a size check against a corpus
func (m *matcher) matchSize(length int) bool {
	// Iterate over all the sizes accepted as valid
	//
	// Sizes codes don't support AND conditions.
	for _, size := range m.Size {
		// Continue if the size doesn't match
		if length != size {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}

// matchWords matches a word check against a corpus.
func (m *matcher) matchWords(corpus string) bool {
	// Iterate over all the words accepted as valid
	for i, word := range m.Words {
		// Continue if the word doesn't match
		if !strings.Contains(corpus, word) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == andCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == orCondition {
			return true
		}

		// If we are at the end of the words, return with true
		if len(m.Words)-1 == i {
			return true
		}
	}
	return false
}

// matchRegex matches a regex check against a corpus
func (m *matcher) matchRegex(corpus string) bool {
	// Iterate over all the regexes accepted as valid
	for i, regex := range m.regexCompiled {
		// Continue if the regex doesn't match
		if !regex.MatchString(corpus) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == andCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == orCondition {
			return true
		}

		// If we are at the end of the regex, return with true
		if len(m.regexCompiled)-1 == i {
			return true
		}
	}
	return false
}

// matchBinary matches a binary check against a corpus
func (m *matcher) matchBinary(corpus string) bool {
	// Iterate over all the words accepted as valid
	for i, binary := range m.Binary {
		// Continue if the word doesn't match
		hexa, _ := hex.DecodeString(binary)
		if !strings.Contains(corpus, string(hexa)) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == andCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == orCondition {
			return true
		}

		// If we are at the end of the words, return with true
		if len(m.Binary)-1 == i {
			return true
		}
	}
	return false
}
