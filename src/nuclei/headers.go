package nuclei

// header represents a HTTP header.
type header struct {
	Key   string
	Value string
}

type headers []header

func (h headers) Len() int { return len(h) }

func (h headers) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h headers) Less(i, j int) bool {
	switch {
	case h[i].Key < h[j].Key:
		return true
	case h[i].Key > h[j].Key:
		return false
	default:
		return h[i].Value < h[j].Value
	}
}
