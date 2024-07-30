package plugin

import (
	"bytes"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/utils/encode"

	"github.com/chainreactors/gogo/v2/pkg"
)

var snmpPublicData = encode.HexDecode("302902010104067075626c6963a01c02049acb0442020100020100300e300c06082b060102010101000500")

func snmpScan(result *pkg.Result) {
	result.Port = "161"
	conn, err := pkg.NewSocket("udp", result.GetTarget(), RunOpt.Delay)
	if err != nil {
		result.Error = err.Error()
		return
	}
	data, err := conn.Request(snmpPublicData, 4096)
	if err != nil {
		result.Error = err.Error()
		return
	}
	if i := bytes.Index(data, []byte{0x0, 0x4}); i != -1 && len(data) > i+3 {
		result.Title = string(data[i+3:])
	}

	result.Open = true
	result.Protocol = "snmp"
	result.Status = "snmp"
	result.AddVuln(&common.Vuln{Name: "snmp_public_auth", Payload: map[string]interface{}{"auth": "public"}, SeverityLevel: fingers.INFO})
}
