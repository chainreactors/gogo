package scan

import (
	"getitle/src/utils"
	"net/http"
	"strings"
)

// -e
func shiroScan(result *utils.Result) {
	var isshiro = false
	target := result.GetURL()
	conn := utils.HttpConn(RunOpt.Delay)
	req := setshirocookie(target, "1")
	resp, err := conn.Do(req)
	if err != nil {
		result.Error = err.Error()
		return
	}
	deleteme := resp.Header.Get("Set-Cookie")
	if strings.Contains(deleteme, "=deleteMe") {
		result.AddFramework(&utils.Framework{Name: "shiro"})
		isshiro = true
	}
	req = setshirocookie(target, "/A29uyYfZg4mT+SUU/3eMAnRlgBWnVrveeiwZ/hz1LlF86NxSmq9dsWpS0U7Q2U+MjbAzaLBCsV7IHb7MQVFItU+ibEkDuyO7WoNGBM4ay8l+oBZo2W2mZcFXG3swJsGXxaZHua3m5jlJNKcCjqy9sX2oRZrm7eSABvUn71vY9NaohbC1i6+FKCRMW9s11/Q")
	resp, err = conn.Do(req)
	if err != nil {
		result.Error = err.Error()
		return
	}
	deleteme = resp.Header.Get("Set-Cookie")
	if isshiro && !strings.Contains(deleteme, "deleteMe") {
		result.AddVuln(&utils.Vuln{Name: "shiro_550"})
	}
	return

}

func setshirocookie(target string, v string) *http.Request {
	req, _ := http.NewRequest("GET", target, nil)
	rememberMe := http.Cookie{Name: "rememberMe", Value: v}
	req.AddCookie(&rememberMe)
	return req
}
