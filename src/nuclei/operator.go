package nuclei

// operators contains the operators that can be applied on protocols
type operators struct {
	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matcher `json:"matchers,omitempty"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	//Extractors []*extractors.Extractor `yaml:"extractors,omitempty"`
	// MatchersCondition is the condition of the matchers
	// whether to use AND or OR. Default is OR.
	MatchersCondition string `json:"matchers-condition,omitempty"`
	// cached variables that may be used along with request.
	matchersCondition conditionType
}

// Result is a result structure created from operators running on data.
type Result struct {
	// Matched is true if any matchers matched
	Matched bool
	// Extracted is true if any result type values were extracted
	//Extracted bool
	// Matches is a map of matcher names that we matched
	Matches map[string]struct{}
	// Extracts contains all the data extracted from inputs
	//Extracts map[string][]string
	// OutputExtracts is the list of extracts to be displayed on screen.
	//OutputExtracts []string
	// DynamicValues contains any dynamic values to be templated
	DynamicValues map[string]interface{}
	// PayloadValues contains payload values provided by user. (Optional)
	PayloadValues map[string]interface{}
}

func (r *operators) compile() error {
	if r.MatchersCondition != "" {
		r.matchersCondition = conditionTypes[r.MatchersCondition]
	} else {
		r.matchersCondition = orCondition
	}
	for _, matcher := range r.Matchers {
		if err := matcher.CompileMatchers(); err != nil {
			return err
		}
	}
	return nil
}

// getMatchersCondition returns the condition for the matchers
func (r *operators) getMatchersCondition() conditionType {
	return r.matchersCondition
}

type matchFunc func(data map[string]interface{}, matcher *matcher) bool

// Execute executes the operators on data and returns a result structure
func (r *operators) Execute(data map[string]interface{}, match matchFunc) (*Result, bool) {
	matcherCondition := r.getMatchersCondition()

	var matches bool
	result := &Result{
		Matches: make(map[string]struct{}),
		//Extracts:      make(map[string][]string),
		DynamicValues: make(map[string]interface{}),
	}

	//// Start with the extractors first and evaluate them.
	//for _, extractor := range r.Extractors {
	//	var extractorResults []string
	//
	//	for match := range extract(data, extractor) {
	//		extractorResults = append(extractorResults, match)
	//
	//		if extractor.Internal {
	//			if _, ok := result.DynamicValues[extractor.Name]; !ok {
	//				result.DynamicValues[extractor.Name] = match
	//			}
	//		} else {
	//			result.OutputExtracts = append(result.OutputExtracts, match)
	//		}
	//	}
	//	if len(extractorResults) > 0 && !extractor.Internal && extractor.Name != "" {
	//		result.Extracts[extractor.Name] = extractorResults
	//	}
	//}

	for _, matcher := range r.Matchers {
		// Check if the matcher matched
		if !match(data, matcher) {
			// If the condition is AND we haven't matched, try next request.
			if matcherCondition == andCondition {
				//if len(result.DynamicValues) > 0 {
				//	return result, true
				//}
				return nil, false
			}
		} else {
			// If the matcher has matched, and its an OR
			// write the first output then move to next matcher.
			if matcherCondition == orCondition && matcher.Name != "" {
				result.Matches[matcher.Name] = struct{}{}
			}
			matches = true
		}
	}

	result.Matched = matches
	//result.Extracted = len(result.OutputExtracts) > 0
	//if len(result.DynamicValues) > 0 {
	//	return result, true
	//}
	// Don't print if we have matchers and they have not matched, irregardless of extractor
	if len(r.Matchers) > 0 && !matches {
		return nil, false
	}
	// Write a final string of output if matcher type is
	// AND or if we have extractors for the mechanism too.
	if matches {
		return result, true
	}
	return nil, true
}
