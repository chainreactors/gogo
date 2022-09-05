//go:build !linux
// +build !linux

package plugin

import "github.com/chainreactors/gogo/pkg"

func arpScan(result *pkg.Result) {
	return
}
