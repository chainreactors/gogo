package network

import (
	"net"
	"time"
)

// Get creates or gets a client for the protocol based on custom configuration
func Get() (*net.Dialer, error) {
	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 3 * time.Second,
		DualStack: true,
	}
	return dialer, nil
}
