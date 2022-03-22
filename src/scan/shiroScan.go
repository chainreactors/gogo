package scan

import (
	"getitle/src/pkg"
	"net/http"
	"strings"
)

// -e
func shiroScan(result *pkg.Result) {
	var isshiro = false
	target := result.GetURL()
	conn := pkg.HttpConn(RunOpt.Delay)
	req := setshirocookie(target, "1")
	resp, err := conn.Do(req)
	if err != nil {
		result.Error = err.Error()
		return
	}
	pkg.Log.Debug("request shiro " + result.GetURL())
	deleteme := resp.Header.Get("Set-Cookie")
	if strings.Contains(deleteme, "=deleteMe") {
		result.AddFramework(&pkg.Framework{Name: "shiro"})
		isshiro = true
	} else {
		return
	}
	req = setshirocookie(target, "/A29uyYfZg4mT+SUU/3eMAnRlgBWnVrveeiwZ/hz1LlF86NxSmq9dsWpS0U7Q2U+MjbAzaLBCsV7IHb7MQVFItU+ibEkDuyO7WoNGBM4ay8l+oBZo2W2mZcFXG3swJsGXxaZHua3m5jlJNKcCjqy9sX2oRZrm7eSABvUn71vY9NaohbC1i6+FKCRMW9s11/Q")
	pkg.Log.Debug("request shiro default key " + result.GetURL())
	resp, err = conn.Do(req)
	if err != nil {
		result.Error = err.Error()
		return
	}
	deleteme = resp.Header.Get("Set-Cookie")
	if isshiro && !strings.Contains(deleteme, "deleteMe") {
		result.AddVuln(&pkg.Vuln{Name: "shiro_550"})
	}
	return

}

func setshirocookie(target string, v string) *http.Request {
	req, _ := http.NewRequest("GET", target, nil)
	rememberMe := http.Cookie{Name: "rememberMe", Value: v}
	req.AddCookie(&rememberMe)
	return req
}
