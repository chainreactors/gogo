package main

import (
	templates "github.com/chainreactors/neutron/templates_gogo"
	"sigs.k8s.io/yaml"
	"strings"
)

func main() {
	examplepoc := `
id: shiro-detect
chain:
  - shiro-default-key
info:
  name: Detect Shiro Framework
  severity: info
  tags: http

requests:
  - method: GET
    path:
      - '{{BaseURL}}'
    headers:
      Cookie: rememberMe=123;

    matchers:
      - type: word
        part: header
        words:
          - "rememberMe=deleteMe"
`

	var t templates.Template
	err := yaml.Unmarshal([]byte(strings.TrimSpace(examplepoc)), &t)
	if err != nil {
		panic(err)
	}

	err = t.Compile(nil)
	if err != nil {
		panic(err)
	}

	res, ok := t.Execute("http://127.0.0.1:8080")
	if ok {
		println(res)
	}
}
