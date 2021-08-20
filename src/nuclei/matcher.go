package nuclei

type Matcher struct {
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

	MatchersCondition string    `json:"matchers-condition"`
	Matchers          []Matcher `json:"matchers"`
}
