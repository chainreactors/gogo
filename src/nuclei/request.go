package nuclei

import (
	"net/http"
	"strings"
)

type Request struct {
	// Operators for the current request go here.
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

	generator     *Generator // optional, only enabled when using payloads
	httpClient    *http.Client
	totalRequests int
}

//var (
//	urlWithPortRegex = regexp.MustCompile(`{{BaseURL}}:(\d+)`)
//)

// Requests returns the total number of requests the YAML rule will perform
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

func (r *Request) Compile() error {
	var err error
	client := createClient(Defaultoption)
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
	//if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
	//	compiled := &r.Operators
	//	if compileErr := compiled.Compile(); compileErr != nil {
	//		return errors.Wrap(compileErr, "could not compile operators")
	//	}
	//	r.CompiledOperators = compiled
	//}

	if len(r.Payloads) > 0 {
		if r.AttackType == "" {
			r.AttackType = "sniper"
		}

		r.generator, err = New(r.Payloads)
		if err != nil {
			return err
		}
	}
	r.totalRequests = r.Requests()
	return nil
}

//func (r *Request) ExecuteRequest(url string,genrequest *generatedRequest){
//
//}

func (r *Request) Execute(url string) {
	generator := r.newGenerator()
	dynamicValues := make(map[string]interface{})
	for {
		req, err := generator.Make(url, dynamicValues)
		if err != nil {
			break
		}
		println(req)
	}
}
