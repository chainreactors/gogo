package nuclei

// Inspired from https://github.com/ffuf/ffuf/blob/master/pkg/input/input.go

import (
	"strings"
)

// Generator is the generator struct for generating payloads
type Generator struct {
	payloads map[string][]string
}

// Type is type of attack
type Type int

// New creates a new generator structure for payload generation
func New(payloads map[string]interface{}) (*Generator, error) {
	generator := &Generator{}

	compiled, err := loadPayloads(payloads)
	if err != nil {
		return nil, err
	}
	generator.payloads = compiled

	return generator, nil
}

// Iterator is a single instance of an iterator for a generator structure
type Iterator struct {
	position    int
	msbIterator int
	total       int
	payloads    []*payloadIterator
}

// NewIterator creates a new iterator for the payloads generator
func (g *Generator) NewIterator() *Iterator {
	var payloads []*payloadIterator

	for name, values := range g.payloads {
		payloads = append(payloads, &payloadIterator{name: name, values: values})
	}
	iterator := &Iterator{
		payloads: payloads,
	}
	iterator.total = iterator.Total()
	return iterator
}

// Reset resets the iterator back to its initial value
func (i *Iterator) Reset() {
	i.position = 0
	i.msbIterator = 0

	for _, payload := range i.payloads {
		payload.resetPosition()
	}
}

// Remaining returns the amount of requests left for the generator.
func (i *Iterator) Remaining() int {
	return i.total - i.position
}

// Total returns the amount of input combinations available
func (i *Iterator) Total() int {
	count := 0
	for _, p := range i.payloads {
		count += len(p.values)
	}
	return count
}

// Value returns the next value for an iterator
func (i *Iterator) Value() (map[string]interface{}, bool) {
	return i.sniperValue()
}

// sniperValue returns a list of all payloads for the iterator
func (i *Iterator) sniperValue() (map[string]interface{}, bool) {
	values := make(map[string]interface{}, 1)

	currentIndex := i.msbIterator
	payload := i.payloads[currentIndex]
	if !payload.next() {
		i.msbIterator++
		if i.msbIterator == len(i.payloads) {
			return nil, false
		}
		return i.sniperValue()
	}
	values[payload.name] = payload.value()
	payload.incrementPosition()
	i.position++
	return values, true
}

// payloadIterator is a single instance of an iterator for a single payload list.
type payloadIterator struct {
	index  int
	name   string
	values []string
}

// next returns true if there are more values in payload iterator
func (i *payloadIterator) next() bool {
	return i.index < len(i.values)
}

// resetPosition resets the position of the payload iterator
func (i *payloadIterator) resetPosition() {
	i.index = 0
}

// incrementPosition increments the position of the payload iterator
func (i *payloadIterator) incrementPosition() {
	i.index++
}

// value returns the value of the payload at an index
func (i *payloadIterator) value() string {
	return i.values[i.index]
}

// loadPayloads loads the input payloads from a map to a data map
func loadPayloads(payloads map[string]interface{}) (map[string][]string, error) {
	loadedPayloads := make(map[string][]string)

	for name, payload := range payloads {
		switch pt := payload.(type) {
		case string:
			elements := strings.Split(pt, "\n")
			//golint:gomnd // this is not a magic number
			loadedPayloads[name] = elements

		case interface{}:
			s := make([]string, len(payload.([]interface{})))
			for i, v := range pt.([]interface{}) {
				s[i] = v.(string)
			}
			loadedPayloads[name] = s
		}
	}
	return loadedPayloads, nil
}
