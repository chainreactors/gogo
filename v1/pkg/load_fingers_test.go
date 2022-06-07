package pkg

import (
	"fmt"
	"testing"
)

func TestLoadFinger(t *testing.T) {
	fingers := LoadFinger("http")
	fmt.Println(fingers)
}

func TestLoadHashFinger(t *testing.T) {
	fingers := LoadFinger("http")
	md5s, mmh3s := LoadHashFinger(fingers)
	fmt.Println(md5s, mmh3s)
}
