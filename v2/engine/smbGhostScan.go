// reference https://github.com/ly4k/SMBGhost
package engine

import (
	"bytes"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/gogo/v2/pkg"
)

var sgpkt = pkg.Decode("YmBgOPAv2NfJgQEG5BlIBSoMHAyMDAwM9VjkKhgYGJhAmEmASYlJhYmBmYlZgFmQGSTHyKDGAKEVwPoJAWYGLqh6BAYBAAAAAP//")

func SMBGhostScan(result *pkg.Result) {
	target := result.GetTarget()
	conn, err := pkg.NewSocket("tcp", target, RunOpt.Delay)
	if err != nil {
		return
	}
	defer conn.Close()
	content, err := conn.Request(sgpkt, 1024)
	if err != nil {
		return
	}
	if len(content) < 76 {
		return
	}
	if bytes.Equal(content[72:74], []byte{0x11, 0x03}) && bytes.Equal(content[74:76], []byte{0x02, 0x00}) {
		result.AddVuln(&common.Vuln{Name: "SMBGHOST", SeverityLevel: common.SeverityCRITICAL})
	}
}
