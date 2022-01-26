package http

import (
	"net/http"
	"regexp"
)

var (
	urlWithPortRegex = regexp.MustCompile(`{{BaseURL}}:(\d+)`)
)

//generatedRequest is a single wrapped generated request for a template request
type generatedRequest struct {
	original *Request
	//rawRequest      *raw.Request
	meta map[string]interface{}
	//pipelinedClient *rawhttp.PipelineClient
	request       *http.Request
	dynamicValues map[string]interface{}
}
