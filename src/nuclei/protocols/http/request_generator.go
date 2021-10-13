package http

import (
	"getitle/src/nuclei"
	"getitle/src/nuclei/protocols"
	. "getitle/src/structutils"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type requestGenerator struct {
	currentIndex    int
	request         *Request
	payloadIterator *protocols.Iterator
	rawRequest      *rawRequest
}

// newGenerator creates a New request generator instance
func (r *Request) newGenerator() *requestGenerator {
	generator := &requestGenerator{request: r}

	if len(r.Payloads) > 0 {
		generator.payloadIterator = r.generator.NewIterator()
	}
	return generator
}

// nextValue returns the next path or the next raw request depending on user input
// It returns false if all the inputs have been exhausted by the generator instance.
func (r *requestGenerator) nextValue() (value string, payloads map[string]interface{}, result bool) {
	// If we have paths, return the next path.
	if len(r.request.Path) > 0 && r.currentIndex < len(r.request.Path) {
		if value := r.request.Path[r.currentIndex]; value != "" {
			r.currentIndex++

			if r.payloadIterator != nil {
				payload, ok := r.payloadIterator.Value()
				if !ok {
					r.payloadIterator.Reset()
					// No more payloads request for us now.
					if len(r.request.Path) == r.currentIndex {
						return "", nil, false
					}
					if value != "" {
						newPayload, ok := r.payloadIterator.Value()
						return value, newPayload, ok
					}
					return "", nil, false
				}
				return value, payload, true
			}
			return value, nil, true
		}
	}

	// If we have raw requests, start with the request at current index.
	// If we are not at the start, then check if the iterator for payloads
	// has finished if there are any.
	//
	// If the iterator has finished for the current raw request
	// then reset it and move on to the next value, otherwise use the last request.
	if len(r.request.Raw) > 0 && r.currentIndex < len(r.request.Raw) {
		if r.payloadIterator != nil {
			payload, ok := r.payloadIterator.Value()
			if !ok {
				r.currentIndex++
				r.payloadIterator.Reset()

				// No more payloads request for us now.
				if len(r.request.Raw) == r.currentIndex {
					return "", nil, false
				}
				if item := r.request.Raw[r.currentIndex]; item != "" {
					newPayload, ok := r.payloadIterator.Value()
					return item, newPayload, ok
				}
				return "", nil, false
			}
			return r.request.Raw[r.currentIndex], payload, true
		}
		if item := r.request.Raw[r.currentIndex]; item != "" {
			r.currentIndex++
			return item, nil, true
		}
	}
	return "", nil, false
}

// Total returns the total number of requests for the generator
func (r *requestGenerator) Total() int {
	if r.payloadIterator != nil {
		return len(r.request.Raw) * r.payloadIterator.Remaining()
	}
	return len(r.request.Path)
}

// Make creates a http request for the provided input.
// It returns io.EOF as error when all the requests have been exhausted.
func (r *requestGenerator) Make(baseURL string, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	// We get the next payload for the request.
	data, payloads, ok := r.nextValue()
	if !ok {
		return nil, io.EOF
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	data, parsed = baseURLWithTemplatePrefs(data, parsed)
	values := MergeMaps(dynamicValues, map[string]interface{}{
		"Hostname": parsed.Host,
	})

	isRawRequest := len(r.request.Raw) > 0
	if !isRawRequest && strings.HasSuffix(parsed.Path, "/") && strings.Contains(data, "{{BaseURL}}/") {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	}
	parsedString := parsed.String()
	values["BaseURL"] = parsedString
	values = MergeMaps(payloads, values)

	// If data contains \n it's a raw request, process it like raw. Else
	// continue with the template based request flow.
	if isRawRequest {
		return r.makeHTTPRequestFromRaw(parsedString, data, values, payloads)
	}
	return r.makeHTTPRequestFromModel(data, values)
}

// baseURLWithTemplatePrefs returns the url for BaseURL keeping
// the template port and path preference over the user provided one.
func baseURLWithTemplatePrefs(data string, parsed *url.URL) (string, *url.URL) {
	// template port preference over input URL port if template has a port
	matches := urlWithPortRegex.FindAllStringSubmatch(data, -1)
	if len(matches) == 0 {
		return data, parsed
	}
	port := matches[0][1]
	parsed.Host = net.JoinHostPort(parsed.Hostname(), port)
	data = strings.Replace(data, ":"+port, "", -1)
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return data, parsed
}

//func (r *Request) executeRequest(reqURL string, request *generatedRequest, previous output.InternalEvent, requestCount int) error {
//}

// MakeHTTPRequestFromModel creates a *http.Request from a request template
func (r *requestGenerator) makeHTTPRequestFromModel(data string, values map[string]interface{}) (*generatedRequest, error) {
	final := nuclei.Replace(data, values)

	// Build a request on the specified URL
	req, err := http.NewRequest(r.request.Method, final, nil)
	if err != nil {
		return nil, err
	}

	request := r.fillRequest(req, values)
	return &generatedRequest{request: request, original: r.request}, nil
}

// makeHTTPRequestFromRaw creates a *http.Request from a raw request
func (r *requestGenerator) makeHTTPRequestFromRaw(baseURL, data string, values, payloads map[string]interface{}) (*generatedRequest, error) {
	return r.handleRawWithPayloads(data, baseURL, values, payloads)
}

// handleRawWithPayloads handles raw requests along with payloads
func (r *requestGenerator) handleRawWithPayloads(rawRequest, baseURL string, values, generatorValues map[string]interface{}) (*generatedRequest, error) {
	// Combine the template payloads along with base
	// request values.
	var request *http.Request
	rawRequest = nuclei.Replace(rawRequest, values)
	rawRequestData, err := parseRaw(rawRequest, baseURL, r.request.Unsafe)
	if err != nil {
		return nil, err
	}
	request = rawRequestData.makeRequest()
	// Unsafe option uses rawhttp library
	if r.request.Unsafe {
		unsafeReq := &generatedRequest{request: request, meta: generatorValues, original: r.request}
		return unsafeReq, nil
	}

	// retryablehttp
	var body io.ReadCloser
	body = ioutil.NopCloser(strings.NewReader(rawRequestData.Data))

	req, err := http.NewRequest(rawRequestData.Method, rawRequestData.FullURL, body)
	if err != nil {
		return nil, err
	}
	for key, value := range rawRequestData.Headers {
		if key == "" {
			continue
		}
		req.Header[key] = []string{value}
		if key == "Host" {
			req.Host = value
		}
	}
	request = r.fillRequest(req, values)
	return &generatedRequest{request: request, meta: generatorValues, original: r.request}, nil
}

// fillRequest fills various headers in the request with values
func (r *requestGenerator) fillRequest(req *http.Request, values map[string]interface{}) *http.Request {
	// Set the header values requested
	for header, value := range r.request.Headers {
		req.Header[header] = []string{nuclei.Replace(value, values)}
		if header == "Host" {
			req.Host = nuclei.Replace(value, values)
		}
	}

	// In case of multiple threads the underlying connection should remain open to allow reuse
	//if r.request.Threads <= 0 && req.header.Get("Connection") == "" {
	//	req.Close = true
	//}

	// Check if the user requested a request body
	if r.request.Body != "" {
		body := nuclei.Replace(r.request.Body, values)
		req.Body = ioutil.NopCloser(strings.NewReader(body))
	}

	// Only set these headers on non raw requests
	if len(r.request.Raw) == 0 {
		setHeader(req, "Accept", "*/*")
		setHeader(req, "Accept-Language", "en")
	}
	return req
}

//
//func (r *requestGenerator) newRawRequest(req *http.Request,rawreq rawRequest,values map[string]interface{})*http.Request{
//	rawreq = ReplaceRawRequest(rawreq,values)
//	req.header = rawreq.headers
//}

// setHeader sets some headers only if the header wasn't supplied by the user
func setHeader(req *http.Request, name, value string) {
	if _, ok := req.Header[name]; !ok {
		req.Header.Set(name, value)
	}
	if name == "Host" {
		req.Host = value
	}
}
