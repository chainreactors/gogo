package http

import (
	"fmt"
	"getitle/src/nuclei/protocols"
	. "getitle/src/structutils"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type Request struct {
	// operators for the current request go here.
	protocols.Operators `json:",inline"`
	// Path contains the path/s for the request
	Path []string `json:"path"`
	// Raw contains raw requests
	Raw []string `json:"raw"`
	ID  string   `json:"id"`
	// Name is the name of the request
	Name string `json:"Name"`
	// AttackType is the attack type
	// Sniper, PitchFork and ClusterBomb. Default is Sniper
	AttackType string `json:"attack"`
	// Method is the request method, whether GET, POST, PUT, etc
	Method string `json:"method"`
	// Body is an optional parameter which contains the request body for POST methods, etc
	Body string `json:"body"`
	// Path contains the path/s for the request variables
	Payloads map[string]interface{} `json:"payloads"`
	// Headers contains headers to send with the request
	Headers map[string]string `json:"headers"`
	// MaxRedirects is the maximum number of redirects that should be followed.
	MaxRedirects int `json:"max-redirects"`
	// PipelineConcurrentConnections is number of connections in pipelining
	Threads int `json:"threads"`

	// MaxSize is the maximum size of http response body to read in bytes.
	MaxSize int `json:"max-size"`

	// CookieReuse is an optional setting that makes cookies shared within requests
	CookieReuse bool `json:"cookie-reuse"`
	// Redirects specifies whether redirects should be followed.
	Redirects bool `json:"redirects"`
	// Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining (race conditions/billions requests)
	// All requests must be indempotent (GET/POST)
	Unsafe bool `json:"unsafe"`
	// ReqCondition automatically assigns numbers to requests and preserves
	// their history for being matched at the end.
	// Currently only works with sequential http requests.
	ReqCondition bool `json:"req-condition"`

	//Matchers []*matcher `json:"matchers,omitempty"`
	//MatchersCondition string `json:"matchers-condition,omitempty"`
	//matchersCondition conditionType

	generator         *protocols.Generator // optional, only enabled when using payloads
	httpClient        *http.Client
	httpresp          *http.Response
	CompiledOperators *protocols.Operators
	attackType        protocols.Type
	totalRequests     int

	options *protocols.ExecuterOptions
	//Result            *protocols.Result
}

//var (
//	urlWithPortRegex = regexp.MustCompile(`{{BaseURL}}:(\d+)`)
//)
// MakeResultEvent creates a result event from internal wrapped event
func (r *Request) MakeResultEvent(wrapped *protocols.InternalWrappedEvent) []*protocols.ResultEvent {
	if len(wrapped.OperatorsResult.DynamicValues) > 0 && !wrapped.OperatorsResult.Matched {
		return nil
	}

	results := make([]*protocols.ResultEvent, 0, len(wrapped.OperatorsResult.Matches)+1)

	// If we have multiple matchers with names, write each of them separately.
	if len(wrapped.OperatorsResult.Matches) > 0 {
		for k := range wrapped.OperatorsResult.Matches {
			data := r.makeResultEventItem(wrapped)
			data.MatcherName = k
			results = append(results, data)
		}
		//} else if len(wrapped.OperatorsResult.Extracts) > 0 {
		//	for k, v := range wrapped.OperatorsResult.Extracts {
		//		data := r.makeResultEventItem(wrapped)
		//		data.ExtractedResults = v
		//		data.ExtractorName = k
		//		results = append(results, data)
		//	}
	} else {
		data := r.makeResultEventItem(wrapped)
		results = append(results, data)
	}
	return results
}

func (r *Request) makeResultEventItem(wrapped *protocols.InternalWrappedEvent) *protocols.ResultEvent {
	data := &protocols.ResultEvent{
		TemplateID: ToString(wrapped.InternalEvent["template-id"]),
		//Info:             wrapped.InternalEvent["template-info"].(map[string]interface{}),
		Type:     "http",
		Host:     ToString(wrapped.InternalEvent["host"]),
		Matched:  ToString(wrapped.InternalEvent["matched"]),
		Metadata: wrapped.OperatorsResult.PayloadValues,
		//ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp: time.Now(),
		IP:        ToString(wrapped.InternalEvent["ip"]),
	}
	return data
}

// requests returns the total number of requests the YAML rule will perform
func (r *Request) Requests() int {
	if r.generator != nil {
		payloadRequests := r.generator.NewIterator().Total() * len(r.Raw)
		return payloadRequests
	}
	if len(r.Raw) > 0 {
		requests := len(r.Raw)
		return requests
	}
	return len(r.Path)
}

func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	r.options = options
	var err error
	connectionConfiguration := &Configuration{
		//Threads:         r.Threads,
		MaxRedirects:    r.MaxRedirects,
		FollowRedirects: r.Redirects,
		CookieReuse:     r.CookieReuse,
	}
	client := createClient(connectionConfiguration)
	r.httpClient = client

	if r.Body != "" && !strings.Contains(r.Body, "\r\n") {
		r.Body = strings.Replace(r.Body, "\n", "\r\n", -1)
	}
	if len(r.Raw) > 0 {
		for i, raw := range r.Raw {
			if !strings.Contains(raw, "\r\n") {
				r.Raw[i] = strings.Replace(raw, "\n", "\r\n", -1)
			}
		}
	}

	// 修改: 只编译一次Matcher
	if r.CompiledOperators == nil && len(r.Matchers) > 0 { // todo extractor
		compiled := &r.Operators
		if compileErr := compiled.Compile(); compileErr != nil {
			return compileErr
		}
		r.CompiledOperators = compiled
	}

	if len(r.Payloads) > 0 {
		attackType := r.AttackType
		if attackType == "" {
			attackType = "sniper"
		}
		r.attackType = protocols.StringToType[attackType]
		r.generator, err = protocols.New(r.Payloads, r.attackType)
		if err != nil {
			return err
		}
	}
	r.totalRequests = r.Requests()
	return nil
}

func (r *Request) ExecuteWithResults(input string, dynamicValues map[string]interface{}, callback protocols.OutputEventCallback) error {
	ok, err := r.ExecuteRequestWithResults(input, dynamicValues, callback)
	if err != nil && !ok {
		return err
	}
	return nil
}

func (r *Request) ExecuteRequestWithResults(url string, dynamicValues map[string]interface{}, callback protocols.OutputEventCallback) (bool, error) {
	generator := r.newGenerator()
	for {
		req, err := generator.Make(url, dynamicValues)
		if err != nil {
			return false, err
		}
		ok, err := r.executeRequest(req, dynamicValues, callback)
		if ok {
			return true, err
		}
	}
}

func (r *Request) executeRequest(request *generatedRequest, dynamicValues map[string]interface{}, callback protocols.OutputEventCallback) (bool, error) {
	resp, err := r.httpClient.Do(request.request)
	if err != nil {
		return false, err
	}
	data := respToMap(resp, request.request)
	event := &protocols.InternalWrappedEvent{InternalEvent: dynamicValues}
	if r.CompiledOperators != nil {
		var ok bool
		event.OperatorsResult, ok = r.CompiledOperators.Execute(data, r.Match, nil)
		if ok && event.OperatorsResult != nil {
			event.OperatorsResult.PayloadValues = request.meta
			event.Results = r.MakeResultEvent(event)
			callback(event)
			return true, err
		}

	}
	return false, err
}

// Match matches a generic data response again a given matcher
func (r *Request) Match(data map[string]interface{}, matcher *protocols.Matcher) bool {
	item, ok := getMatchPart(matcher.Part, data)
	if !ok {
		return false
	}

	switch matcher.GetType() {
	case protocols.StatusMatcher:
		statusCode, ok := data["status_code"]
		if !ok {
			return false
		}
		status, ok := statusCode.(int)
		if !ok {
			return false
		}
		return matcher.Result(matcher.MatchStatusCode(status))
	case protocols.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(item)))
	case protocols.WordsMatcher:
		return matcher.Result(matcher.MatchWords(item))
	case protocols.RegexMatcher:
		return matcher.Result(matcher.MatchRegex(item))
	case protocols.BinaryMatcher:
		return matcher.Result(matcher.MatchBinary(item))
	}
	return false
}

// getMatchPart returns the match part honoring "all" matchers + others.
func getMatchPart(part string, data map[string]interface{}) (string, bool) {
	if part == "header" {
		part = "all_headers"
	}
	var itemStr string

	if part == "all" {
		builder := &strings.Builder{}
		builder.WriteString(ToString(data["body"]))
		builder.WriteString(ToString(data["all_headers"]))
		itemStr = builder.String()
	} else {
		item, ok := data[part]
		if !ok {
			return "", false
		}
		itemStr = ToString(item)
	}
	return itemStr, true
}

func respToMap(resp *http.Response, req *http.Request) map[string]interface{} {
	data := make(map[string]interface{})
	data["host"] = req.Host
	data["request"] = req
	data["response"] = resp
	data["content_length"] = resp.ContentLength
	data["status_code"] = resp.StatusCode
	bodybytes, _ := ioutil.ReadAll(resp.Body)
	data["body"] = string(bodybytes)
	data["url"] = req.URL

	for k, v := range resp.Header {
		for _, i := range v {
			data["all_headers"] = ToString(data["all_headers"]) + fmt.Sprintf("%s: %s\r\n", k, i)
		}
	}

	for _, cookie := range resp.Cookies() {
		data[strings.ToLower(cookie.Name)] = cookie.Value
	}
	for k, v := range resp.Header {
		k = strings.ToLower(strings.Replace(strings.TrimSpace(k), "-", "_", -1))
		data[k] = strings.Join(v, " ")
	}
	resp.Body.Close()
	return data
}

func (r *Request) GetID() string {
	return r.ID
}
