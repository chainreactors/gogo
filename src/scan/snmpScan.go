package scan

import (
	"getitle/src/utils"
	"github.com/alouca/gosnmp"
)

func snmpScan(target string, result *utils.Result) {
	var err error
	s, err := gosnmp.NewGoSNMP(target, "public", gosnmp.Version2c, int64(Delay+2))
	if err != nil {
		//log.Fatal(err)
		return
	}
	resp, err := s.Get(".1.3.6.1.2.1.1.1.0")
	if err != nil {
		return
	}
	result.Stat = true
	result.Protocol = "udp"
	result.HttpStat = "snmp"
	if len(resp.Variables) > 0 {
		result.Midware = resp.Variables[0].Value.(string)
	}
}
