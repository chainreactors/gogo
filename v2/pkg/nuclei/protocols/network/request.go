package network

import (
	"encoding/hex"
	"errors"
	"github.com/chainreactors/gogo/v2/pkg/nuclei"
	protocols "github.com/chainreactors/gogo/v2/pkg/nuclei/protocols"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

var _ protocols.Request = &Request{}

func (request *Request) getMatchPart(part string, data protocols.InternalEvent) (string, bool) {
	switch part {
	case "body", "all", "":
		part = "data"
	}

	item, ok := data[part]
	if !ok {
		return "", false
	}
	itemStr := utils.ToString(item)

	return itemStr, true
}

func (r *Request) Match(data map[string]interface{}, matcher *protocols.Matcher) bool {
	itemStr, ok := r.getMatchPart(matcher.Part, data)
	if !ok {
		return ok
	}

	switch matcher.GetType() {
	case protocols.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(itemStr)))
	case protocols.WordsMatcher:
		return matcher.Result(matcher.MatchWords(itemStr))
	case protocols.RegexMatcher:
		return matcher.Result(matcher.MatchRegex(itemStr))
	case protocols.BinaryMatcher:
		return matcher.Result(matcher.MatchBinary(itemStr))
	}
	return false
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (request *Request) Extract(data map[string]interface{}, extractor *protocols.Extractor) map[string]struct{} {
	itemStr, ok := request.getMatchPart(extractor.Part, data)
	if !ok {
		return nil
	}

	switch extractor.GetType() {
	case protocols.RegexExtractor:
		return extractor.ExtractRegex(itemStr)
	case protocols.KValExtractor:
		return extractor.ExtractKval(data)
	}
	return nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, dynamicValues map[string]interface{}, callback protocols.OutputEventCallback) error {
	address, err := getAddress(input)
	if err != nil {
		return err
	}
	dynamicValues = utils.MergeMaps(dynamicValues, map[string]interface{}{"Hostname": address})
	for _, kv := range r.addresses {
		variables := generateNetworkVariables(address)
		actualAddress := nuclei.Replace(kv.address, variables)
		err = r.executeAddress(variables, actualAddress, address, input, kv.tls, dynamicValues, callback)
		if err != nil {
			continue
		}
	}
	return nil
}

// executeAddress executes the request for an address
func (r *Request) executeAddress(variables map[string]interface{}, actualAddress, address, input string, shouldUseTLS bool, dynamicValues map[string]interface{}, callback protocols.OutputEventCallback) error {
	if !strings.Contains(actualAddress, ":") {
		err := errors.New("no port provided in network protocol request")
		return err
	}
	payloads := protocols.BuildPayloadFromOptions(r.options.Options)
	// add Hostname variable to the payload
	//payloads = nuclei.MergeMaps(payloads, map[string]interface{}{"Hostname": address})

	if r.generator != nil {
		iterator := r.generator.NewIterator()

		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}
			value = utils.MergeMaps(value, payloads)
			if err := r.executeRequestWithPayloads(variables, actualAddress, address, input, shouldUseTLS, value, dynamicValues, callback); err != nil {
				return err
			}
		}
	} else {
		value := protocols.CopyMap(payloads)

		if err := r.executeRequestWithPayloads(variables, actualAddress, address, input, shouldUseTLS, value, dynamicValues, callback); err != nil {
			return err
		}
	}
	return nil
}

func (r *Request) executeRequestWithPayloads(variables map[string]interface{}, actualAddress, address, input string, shouldUseTLS bool, payloads map[string]interface{}, dynamicValues map[string]interface{}, callback protocols.OutputEventCallback) error {
	var (
		//hostname string
		conn net.Conn
		err  error
	)

	//if host, _, splitErr := net.SplitHostPort(actualAddress); splitErr == nil {
	//	hostname = host
	//}

	if shouldUseTLS {
		//conn, err = r.dialer.DialTLS(context.Background(), "tcp", actualAddress)
	} else {
		conn, err = r.dialer.Dial("tcp", actualAddress)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(2) * time.Second))

	responseBuilder := &strings.Builder{}
	reqBuilder := &strings.Builder{}

	inputEvents := make(map[string]interface{})
	for _, input := range r.Inputs {
		var data []byte

		switch input.Type {
		case "hex":
			data, err = hex.DecodeString(input.Data)
		default:
			data = []byte(input.Data)
		}
		if err != nil {
			return err
		}
		reqBuilder.Grow(len(input.Data))

		finalData := []byte(nuclei.Replace(string(data), payloads))
		//if dataErr != nil {
		//	r.options.Output.Request(r.options.TemplateID, address, "network", dataErr)
		//	r.options.Progress.IncrementFailedRequestsBy(1)
		//	return errors.Wrap(dataErr, "could not evaluate template expressions")
		//}
		reqBuilder.Write(finalData)

		_, err = conn.Write(finalData)
		if err != nil {
			return err
		}

		if input.Read > 0 {
			buffer := make([]byte, input.Read)
			n, _ := conn.Read(buffer)
			responseBuilder.Write(buffer[:n])

			bufferStr := string(buffer[:n])
			if input.Name != "" {
				inputEvents[input.Name] = bufferStr
			}

			// Run any internal extractors for the request here and add found values to map.
			if r.CompiledOperators != nil {
				values := r.CompiledOperators.ExecuteInternalExtractors(map[string]interface{}{input.Name: bufferStr}, r.Extract)
				for k, v := range values {
					payloads[k] = v
				}
			}
		}
	}
	//r.options.Progress.IncrementRequests()

	bufferSize := 1024
	if r.ReadSize != 0 {
		bufferSize = r.ReadSize
	}

	var (
		final []byte
		n     int
	)
	if r.ReadAll {
		readInterval := time.NewTimer(time.Second * 1)
		// stop the timer and drain the channel
		closeTimer := func(t *time.Timer) {
			if !t.Stop() {
				<-t.C
			}
		}
	readSocket:
		for {
			select {
			case <-readInterval.C:
				closeTimer(readInterval)
				break readSocket
			default:
				buf := make([]byte, bufferSize)
				nBuf, err := conn.Read(buf)
				if err != nil {
					if err == io.EOF {
						break readSocket
					} else {
						return err
					}
				}
				responseBuilder.Write(buf[:nBuf])
				final = append(final, buf[:nBuf]...)
				n += nBuf
			}
		}
	} else {
		final = make([]byte, bufferSize)
		time.Sleep(time.Duration(r.ReadSize/10) * time.Millisecond)
		n, err = conn.Read(final)
		if err != nil && err != io.EOF {
			return err
		}
		responseBuilder.Write(final[:n])
	}

	//outputEvent := r.responseToDSLMap(reqBuilder.String(), string(final[:n]), responseBuilder.String(), input, actualAddress)
	//outputEvent["ip"] = r.dialer.GetDialedIP(hostname)
	//for k, v := range dynamicValues {
	//	outputEvent[k] = v
	//}
	//for k, v := range payloads {
	//	outputEvent[k] = v
	//}
	//for k, v := range inputEvents {
	//	outputEvent[k] = v
	//}
	event := &protocols.InternalWrappedEvent{InternalEvent: dynamicValues}
	if r.CompiledOperators != nil {
		result, ok := r.CompiledOperators.Execute(map[string]interface{}{"data": responseBuilder.String()}, r.Match, r.Extract)
		if ok && result != nil {
			event.OperatorsResult = result
			event.OperatorsResult.PayloadValues = payloads
			//event.Results = r.MakeResultEvent(event)
		}
	}
	callback(event)

	//event := &output.InternalWrappedEvent{InternalEvent: outputEvent}

	return nil
}

// getAddress returns the address of the host to make request to
func getAddress(toTest string) (string, error) {
	if strings.Contains(toTest, "://") {
		parsed, err := url.Parse(toTest)
		if err != nil {
			return "", err
		}
		toTest = parsed.Host
	}
	return toTest, nil
}

func generateNetworkVariables(input string) map[string]interface{} {
	if !strings.Contains(input, ":") {
		return map[string]interface{}{"Hostname": input, "Host": input}
	}
	host, port, err := net.SplitHostPort(input)
	if err != nil {
		return map[string]interface{}{"Hostname": input}
	}
	return map[string]interface{}{
		"Host":     host,
		"Port":     port,
		"Hostname": input,
	}
}
