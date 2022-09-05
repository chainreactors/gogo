package plugin

import (
	"bytes"
	"github.com/M09ic/go-ntlmssp"
	"github.com/chainreactors/gogo/pkg"
	"github.com/chainreactors/gogo/pkg/utils"
)

var data = pkg.Decode("YmXgZhZgYGCoYNBgYGZgYNghsAPEZWAEY0aGBSAGAwPDAQjlBiJYYju6XsucFJz/goNBW8AjgYmBgYGLCaLAL8THNzg4AKyfvYljEQMaYGPcKMvAwMAPAAAA//8=")

func wmiScan(result *pkg.Result) {
	result.Port = "135"
	target := result.GetTarget()
	conn, err := pkg.NewSocket("tcp", target, RunOpt.Delay)
	if err != nil {
		return
	}
	defer conn.Close()

	result.Open = true
	ret, err := conn.Request(data, 4096)
	if err != nil {
		return
	}

	off_ntlm := bytes.Index(ret, []byte("NTLMSSP"))
	if off_ntlm != -1 {
		result.Protocol = "wmi"
		result.HttpStat = "WMI"
		tinfo := utils.ToStringMap(ntlmssp.NTLMInfo(ret[off_ntlm:]))
		result.AddNTLMInfo(tinfo, "wmi")
	}
}
