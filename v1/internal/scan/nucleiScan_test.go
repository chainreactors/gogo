package scan

import (
	"getitle/v1/pkg"
	"strings"
	"testing"
)

func TestRequest(t *testing.T) {
	conn := pkg.HttpConn(2)
	resp, _ := conn.Post("http://10.43.252.95/login.do", "application/x-www-form-urlencoded", strings.NewReader("auth=YWRtaW46YWRtaW4="))
	println(resp)
	print(pkg.GetHttpRaw(resp))
}
