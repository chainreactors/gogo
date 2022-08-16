package plugin

import (
	"github.com/mdlayher/arp"
	"net"
	"testing"
	"time"
)

func TestArp(t *testing.T) {
	// Ensure valid network interface
	ifi, err := net.InterfaceByName("WLAN")
	if err != nil {
		println(err.Error())
		return
	}
	// Set up ARP client with socket
	c, err := arp.Dial(ifi)
	if err != nil {
		println(err.Error())
		return
	}
	defer c.Close()

	// Set request deadline from flag
	if err := c.SetDeadline(time.Now().Add(1)); err != nil {
		println(err.Error())
		return
	}

	// Request hardware address for IP address
	host := net.ParseIP("192.168.31.1").To4()
	mac, err := c.Resolve(host)
	if err != nil {
		println(err.Error())
		return
	}
	println(host, mac)
	return
}
