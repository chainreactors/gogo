//go:build linux
// +build linux

package scan

import (
	"getitle/src/pkg"
	"github.com/mdlayher/arp"
	"net"
	"time"
)

func arpScan(result *pkg.Result) {
	// Set up ARP client with socket
	c, err := arp.Dial(RunOpt.Interface)
	if err != nil {
		println(err.Error())
		return
	}
	defer c.Close()

	// Set request deadline from flag
	if err := c.SetDeadline(time.Now().Add(time.Duration(RunOpt.Delay/2) * time.Second)); err != nil {
		result.Error = err.Error()
		return
	}

	// Request hardware address for IP address
	pkg.Log.Debug("request arp " + result.GetTarget())
	mac, err := c.Resolve(net.ParseIP(result.Ip))
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Open = true
	result.HttpStat = "arp"
	result.Protocol = "arp"
	result.Title = mac.String()
	return
}
