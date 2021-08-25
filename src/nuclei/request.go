package nuclei

import (
	"io/ioutil"
	"net/http"
	"strings"
)

type Request struct {
	// operators for the current request go here.
	operators `yaml:",inline"`
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

	generator         *generator // optional, only enabled when using payloads
	httpClient        *http.Client
	httpresp          *http.Response
	CompiledOperators *operators
	attackType        Type
	totalRequests     int
	Result            *Result
}

//var (
//	urlWithPortRegex = regexp.MustCompile(`{{BaseURL}}:(\d+)`)
//)

// requests returns the total number of requests the YAML rule will perform
func (r *Request) requests() int {
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

func (r *Request) Compile(opt Options) error {
	var err error
	client := createClient(opt)
	r.httpClient = client

	if r.Body != "" && !strings.Contains(r.Body, "\r\n") {
		r.Body = strings.ReplaceAll(r.Body, "\n", "\r\n")
	}
	if len(r.Raw) > 0 {
		for i, raw := range r.Raw {
			if !strings.Contains(raw, "\r\n") {
				r.Raw[i] = strings.ReplaceAll(raw, "\n", "\r\n")
			}
		}
	}

	// 修改: 只编译一次Matcher
	if r.CompiledOperators == nil && len(r.Matchers) > 0 { // todo extractor
		compiled := &r.operators
		if compileErr := compiled.compile(); compileErr != nil {
			return compileErr
		}
		r.CompiledOperators = compiled
	}

	if len(r.Payloads) > 0 {
		attackType := r.AttackType
		if attackType == "" {
			attackType = "sniper"
		}
		r.attackType = StringToType[attackType]
		r.generator, err = New(r.Payloads, r.attackType)
		if err != nil {
			return err
		}
	}
	r.totalRequests = r.requests()
	return nil
}

func (r *Request) ExecuteRequestWithResults(url string, opt Options) (*Result, error) {
	var err error
	err = r.Compile(opt)
	if err != nil {
		print(err.Error())
	}
	generator := r.newGenerator()
	dynamicValues := make(map[string]interface{})
	for {
		req, err := generator.Make(url, dynamicValues)
		if err != nil {
			break
		}
		ok, err := r.executeRequest(req, dynamicValues)
		if ok {
			return r.Result, err
		}
	}
	return nil, err
}

func (r *Request) executeRequest(request *generatedRequest, previous map[string]interface{}) (bool, error) {
	resp, err := r.httpClient.Do(request.request)
	if err != nil {
		return false, err
	}
	data := respToMap(resp, request.request)
	res, ok := r.CompiledOperators.Execute(data, r.Match)
	if ok && res.Matched {
		res.PayloadValues = request.meta
		r.Result = res
		return true, err
	}
	return false, err
}

// Match matches a generic data response again a given matcher
func (r *Request) Match(data map[string]interface{}, matcher *matcher) bool {
	item, ok := getMatchPart(matcher.Part, data)
	if !ok {
		return false
	}

	switch matcher.getType() {
	case statusMatcher:
		statusCode, ok := data["status_code"]
		if !ok {
			return false
		}
		status, ok := statusCode.(int)
		if !ok {
			return false
		}
		return matcher.result(matcher.matchStatusCode(status))
	case sizeMatcher:
		return matcher.result(matcher.matchSize(len(item)))
	case wordsMatcher:
		return matcher.result(matcher.matchWords(item))
	case regexMatcher:
		return matcher.result(matcher.matchRegex(item))
	case binaryMatcher:
		return matcher.result(matcher.matchBinary(item))
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
		builder.WriteString(toString(data["body"]))
		builder.WriteString(toString(data["all_headers"]))
		itemStr = builder.String()
	} else {
		item, ok := data[part]
		if !ok {
			return "", false
		}
		itemStr = toString(item)
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
	for _, cookie := range resp.Cookies() {
		data[strings.ToLower(cookie.Name)] = cookie.Value
	}
	for k, v := range resp.Header {
		k = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(k), "-", "_"))
		data[k] = strings.Join(v, " ")
	}
	resp.Body.Close()
	return data
}
