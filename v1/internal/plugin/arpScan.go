//go:build !linux
// +build !linux

package plugin

import "github.com/chainreactors/gogo/v1/pkg"

func arpScan(result *pkg.Result) {
	return
}
