package protocols

import "time"

type ExecuterOptions struct {
	// TemplateID is the ID of the template for the request
	TemplateID string
	// TemplateInfo contains information block of the template request
	TemplateInfo map[string]interface{}

	Options *Options
}

// Executer is an interface implemented any protocol based request executer.
type Executer interface {
	// Compile compiles the execution generators preparing any requests possible.
	Compile() error
	// Requests returns the total number of requests the rule will perform
	Requests() int
	// Execute executes the protocol group and returns true or false if results were found.
	Execute(input string) (*Result, error)
	// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
	//ExecuteWithResults(input string) error
}

// Request is an interface implemented any protocol based request generator.
type Request interface {
	// Compile compiles the request generators preparing any requests possible.
	Compile(options *ExecuterOptions) error
	// Requests returns the total number of requests the rule will perform
	Requests() int
	// GetID returns the ID for the request if any. IDs are used for multi-request
	// condition matching. So, two requests can be sent and their match can
	// be evaluated from the third request by using the IDs for both requests.
	//GetID() string
	// Match performs matching operation for a matcher on model and returns true or false.
	Match(data map[string]interface{}, matcher *Matcher) bool
	// Extract performs extracting operation for a extractor on model and returns true or false.
	//Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}
	// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
	ExecuteWithResults(input string, dynamicValues map[string]interface{}, callback OutputEventCallback) error
}

//type InternalEvent map[string]interface{}

type ResultEvent struct {
	//TemplateID is the ID of the template for the result.
	TemplateID string `json:"templateID"`
	// Info contains information block of the template for the result.
	//Info map[string]interface{} `json:"info,inline"`
	// MatcherName is the name of the matcher matched if any.
	MatcherName string `json:"matcher_name,omitempty"`
	// ExtractorName is the name of the extractor matched if any.
	ExtractorName string `json:"extractor_name,omitempty"`
	// Type is the type of the result event.
	Type string `json:"type"`
	// Host is the host input on which match was found.
	Host string `json:"host,omitempty"`
	// Path is the path input on which match was found.
	Path string `json:"path,omitempty"`
	// Matched contains the matched input in its transformed form.
	Matched string `json:"matched,omitempty"`
	// ExtractedResults contains the extraction result from the inputs.
	ExtractedResults []string `json:"extracted_results,omitempty"`
	// Request is the optional dumped request for the match.
	//Request string `json:"request,omitempty"`
	// Response is the optional dumped response for the match.
	//Response string `json:"response,omitempty"`
	// Metadata contains any optional metadata for the event
	Metadata map[string]interface{} `json:"meta,omitempty"`
	// IP is the IP address for the found result event.
	IP string `json:"ip,omitempty"`
	// Timestamp is the time the result was found at.
	Timestamp time.Time `json:"timestamp"`
	// Interaction is the full details of interactsh interaction.
	//Interaction *server.Interaction `json:"interaction,omitempty"`

	//FileToIndexPosition map[string]int `json:"-"`
}

type InternalEvent map[string]interface{}

type InternalWrappedEvent struct {
	InternalEvent   InternalEvent
	Results         []*ResultEvent
	OperatorsResult *Result
}

type OutputEventCallback func(result *InternalWrappedEvent)
