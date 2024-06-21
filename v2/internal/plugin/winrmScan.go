package plugin

import (
	"encoding/base64"
	"fmt"
	"github.com/M09ic/go-ntlmssp"
	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils/iutils"
	"net/http"
	"strings"
)

func winrmScan(result *pkg.Result) {
	if pkg.OPSEC {
		return
	}
	result.Port = "5985"
	uri := fmt.Sprintf("http://%s/wsman", result.GetTarget())
	logs.Log.Debugf("winrm scan %s", uri)
	conn := pkg.HttpConn(RunOpt.Delay)
	req, _ := http.NewRequest("POST", uri, nil)
	req.Header.Add("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Add("User-Agent", "Microsoft WinRM Client")
	req.Header.Add("Authorization", "Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")
	resp, err := conn.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	result.Open = true
	ntlminfo := resp.Header.Get("Www-Authenticate")
	if ntlminfo == "" || !strings.HasPrefix(ntlminfo, "Negotiate ") {
		return
	}
	tinfo, err := base64.StdEncoding.DecodeString(ntlminfo[10:])
	if err != nil {
		return
	}
	result.Status = "winrm"
	result.Protocol = "winrm"
	result.AddNTLMInfo(iutils.ToStringMap(ntlmssp.NTLMInfo(tinfo)), "winrm")
}
