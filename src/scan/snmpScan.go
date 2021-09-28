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
	result.Open = true
	result.Protocol = "snmp"
	result.HttpStat = "snmp"
	if len(resp.Variables) > 0 {
		result.AddVuln(utils.Vuln{Name: "snmp_default_auth", Payload: map[string]interface{}{"auth": "public"}})
		result.Title = resp.Variables[0].Value.(string)
	}
}
