//go:build !linux
// +build !linux

package scan

import "github.com/chainreactors/gogo/v1/pkg"

func arpScan(result *pkg.Result) {
	return
}
