package pkg

import (
	"path"
	"testing"
)

func TestEncode(t *testing.T) {
	print(path.Base("192.168.1.1/24"))
}
