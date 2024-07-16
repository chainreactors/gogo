module github.com/chainreactors/gogo/v2

go 1.10

require (
	github.com/M09ic/go-ntlmssp v0.0.0-20230312133735-dcccd454dfe0
	github.com/chainreactors/files v0.0.0-20231123083421-cea5b4ad18a8
	github.com/chainreactors/fingers v0.0.0-20240716060852-2fda69a0d7fa
	github.com/chainreactors/logs v0.0.0-20240207121836-c946f072f81f
	github.com/chainreactors/neutron v0.0.0-20240715184426-66d4353a43c6
	github.com/chainreactors/parsers v0.0.0-20240708072709-07deeece7ce2
	github.com/chainreactors/utils v0.0.0-20240715093949-e1faa388e281
	github.com/jessevdk/go-flags v1.5.0
	github.com/panjf2000/ants/v2 v2.9.1
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/net v0.21.0
	sigs.k8s.io/yaml v1.4.0 // generate only
)

replace golang.org/x/net => golang.org/x/net v0.0.0-20200202094626-16171245cfb2

replace golang.org/x/text => golang.org/x/text v0.3.3
