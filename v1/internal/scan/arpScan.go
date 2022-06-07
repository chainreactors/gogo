//go:build !linux
// +build !linux

package scan

import "getitle/v1/pkg"

func arpScan(result *pkg.Result) {
	return
}
