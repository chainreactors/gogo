package scan

import (
	. "getitle/v1/pkg"
	. "getitle/v1/pkg/fingers"
	"net/http"
	"strings"
)

// -e
func shiroScan(result *Result) {
	var isshiro = false
	url := result.GetURL()
	conn := result.GetHttpConn(RunOpt.Delay)
	req := setshirocookie(url, "1")
	resp, err := conn.Do(req)
	if err != nil {
		result.Error = err.Error()
		return
	}
	Log.Debug("request shiro " + url)
	deleteme := resp.Header.Get("Set-Cookie")
	if strings.Contains(deleteme, "=deleteMe") {
		result.AddFramework(&Framework{Name: "shiro", Version: "active"})
		isshiro = true
	} else {
		return
	}
	req = setshirocookie(url, "/A29uyYfZg4mT+SUU/3eMAnRlgBWnVrveeiwZ/hz1LlF86NxSmq9dsWpS0U7Q2U+MjbAzaLBCsV7IHb7MQVFItU+ibEkDuyO7WoNGBM4ay8l+oBZo2W2mZcFXG3swJsGXxaZHua3m5jlJNKcCjqy9sX2oRZrm7eSABvUn71vY9NaohbC1i6+FKCRMW9s11/Q")
	Log.Debug("request shiro default key " + url)
	resp, err = conn.Do(req)
	if err != nil {
		result.Error = err.Error()
		return
	}
	deleteme = resp.Header.Get("Set-Cookie")
	if isshiro && !strings.Contains(deleteme, "deleteMe") {
		result.AddVuln(&Vuln{Name: "shiro_550", Payload: map[string]interface{}{"key": "kPH+bIxk5D2deZiIxcaaaA=="}})
	}
	return

}

func setshirocookie(target string, v string) *http.Request {
	req, _ := http.NewRequest("GET", target, nil)
	rememberMe := http.Cookie{Name: "rememberMe", Value: v}
	req.AddCookie(&rememberMe)
	return req
}
