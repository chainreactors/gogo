package network

import (
	"encoding/hex"
	"errors"
	"getitle/src/nuclei"
	"getitle/src/nuclei/protocols"
	"getitle/src/structutils"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

var _ protocols.Request = &Request{}

func (r *Request) Match(data map[string]interface{}, matcher *protocols.Matcher) bool {
	partString := matcher.Part
	switch partString {
	case "body", "all", "":
		partString = "data"
	}

	item, ok := data[partString]
	if !ok {
		return false
	}
	itemStr := structutils.ToString(item)

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

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, dynamicValues map[string]interface{}, callback protocols.OutputEventCallback) error {
	address, err := getAddress(input)
	if err != nil {
		return err
	}

	for _, kv := range r.addresses {
		actualAddress := nuclei.Replace(kv.ip, map[string]interface{}{"Hostname": address})
		if kv.port != "" {
			if strings.Contains(address, ":") {
				actualAddress, _, _ = net.SplitHostPort(actualAddress)
			}
			actualAddress = net.JoinHostPort(actualAddress, kv.port)
		}

		err = r.executeAddress(actualAddress, address, input, kv.tls, dynamicValues, callback)
		if err != nil {
			continue
		}
	}
	return nil
}

// executeAddress executes the request for an address
func (r *Request) executeAddress(actualAddress, address, input string, shouldUseTLS bool, dynamicValues map[string]interface{}, callback protocols.OutputEventCallback) error {
	if !strings.Contains(actualAddress, ":") {
		err := errors.New("no port provided in network protocol request")
		return err
	}

	if r.generator != nil {
		iterator := r.generator.NewIterator()

		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}
			if err := r.executeRequestWithPayloads(actualAddress, address, input, shouldUseTLS, value, dynamicValues, callback); err != nil {
				return err
			}
		}
	} else {
		value := make(map[string]interface{})
		if err := r.executeRequestWithPayloads(actualAddress, address, input, shouldUseTLS, value, dynamicValues, callback); err != nil {
			return err
		}
	}
	return nil
}

func (r *Request) executeRequestWithPayloads(actualAddress, address, input string, shouldUseTLS bool, payloads map[string]interface{}, dynamicValues map[string]interface{}, callback protocols.OutputEventCallback) error {
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

		//finalData, dataErr := expressions.EvaluateByte(data, payloads)
		//if dataErr != nil {
		//	r.options.Output.Request(r.options.TemplateID, address, "network", dataErr)
		//	r.options.Progress.IncrementFailedRequestsBy(1)
		//	return errors.Wrap(dataErr, "could not evaluate template expressions")
		//}
		reqBuilder.Write(data)

		_, err = conn.Write(data)
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
			//if r.CompiledOperators != nil {
			//	values := r.CompiledOperators.ExecuteInternalExtractors(map[string]interface{}{input.Name: bufferStr}, r.Extract)
			//	for k, v := range values {
			//		payloads[k] = v
			//	}
			//}
		}
	}
	//r.options.Progress.IncrementRequests()

	bufferSize := 1024
	if r.ReadSize != 0 {
		bufferSize = r.ReadSize
	}
	final := make([]byte, bufferSize)
	n, err := conn.Read(final)
	if err != nil && err != io.EOF {
		return err
	}
	responseBuilder.Write(final[:n])

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
		result, ok := r.CompiledOperators.Execute(map[string]interface{}{"data": responseBuilder.String()}, r.Match)
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
