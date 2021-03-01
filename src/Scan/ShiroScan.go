package Scan

import (
	"getitle/src/Utils"
	"net/http"
	"strings"
)

func ShiroScan(result *Utils.Result) *Utils.Result {
	var isshiro = false
	target := Utils.GetURL(*result)
	conn := Utils.HttpConn(Delay)
	req := setshirocookie(target, "1")
	resp, err := conn.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	deleteme := resp.Header.Get("Set-Cookie")
	if strings.Contains(deleteme, "=deleteme") {
		result.Framework = "shiro"
		isshiro = true
	}
	req = setshirocookie(target, "/A29uyYfZg4mT+SUU/3eMAnRlgBWnVrveeiwZ/hz1LlF86NxSmq9dsWpS0U7Q2U+MjbAzaLBCsV7IHb7MQVFItU+ibEkDuyO7WoNGBM4ay8l+oBZo2W2mZcFXG3swJsGXxaZHua3m5jlJNKcCjqy9sX2oRZrm7eSABvUn71vY9NaohbC1i6+FKCRMW9s11/Q")
	resp, err = conn.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	deleteme = resp.Header.Get("Set-Cookie")
	if isshiro && !strings.Contains(deleteme, "deleteMe") {
		result.Vuln = "shiro 550"
	}
	return result

}

func setshirocookie(target string, v string) *http.Request {
	req, _ := http.NewRequest("GET", target, nil)
	rememberMe := http.Cookie{Name: "rememberMe", Value: v}
	req.AddCookie(&rememberMe)
	return req
}
