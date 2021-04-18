package Scan

import (
	"getitle/src/Utils"
	"github.com/alouca/gosnmp"
)

func SnmpScan(target string, result *Utils.Result) {
	s, err := gosnmp.NewGoSNMP(target, "public", gosnmp.Version2c, int64(Delay+2))
	if err != nil {
		//log.Fatal(err)
	}
	resp, err := s.Get(".1.3.6.1.2.1.1.1.0")
	if err != nil {
		return
	}
	result.Stat = "OPEN"
	result.Protocol = "udp"
	result.HttpStat = "snmp"
	result.Midware = resp.Variables[0].Value.(string)
}
