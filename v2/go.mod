module github.com/chainreactors/gogo/v2

go 1.10

require (
	github.com/M09ic/go-ntlmssp v0.0.0-20230312133735-dcccd454dfe0
	github.com/chainreactors/fingers v1.0.2-0.20251202165109-ce668e80a672
	github.com/chainreactors/logs v0.0.0-20241115105204-6132e39f5261
	github.com/chainreactors/neutron v0.0.0-20250113061151-32771f256b1f
	github.com/chainreactors/parsers v0.0.0-20251202162218-4b2258465d0a
	github.com/chainreactors/proxyclient v1.0.3
	github.com/chainreactors/utils v0.0.0-20250831165528-f06246b0f311
	github.com/jessevdk/go-flags v1.6.1
	github.com/panjf2000/ants/v2 v2.9.1
	github.com/stretchr/testify v1.10.0
	golang.org/x/net v0.23.0
	gopkg.in/yaml.v3 v3.0.1
	sigs.k8s.io/yaml v1.4.0 // generate only
)

replace (
	github.com/chainreactors/proxyclient => github.com/chainreactors/proxyclient v1.0.3
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20191205180655-e7c4368fe9dd
	golang.org/x/net => golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200223170610-d5e6a3e2c0ae
	golang.org/x/text => golang.org/x/text v0.3.3
)
