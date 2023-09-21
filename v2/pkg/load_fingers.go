package pkg

import (
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/utils/iutils"
)

var (
	AllHttpFingers     fingers.Fingers
	SocketFingers      fingers.FingerMapper
	ActiveFavicons     []*fingers.Favicons
	ActiveHttpFingers  fingers.Fingers
	PassiveHttpFingers fingers.Fingers
)

// LoadFinger 加载指纹到全局变量
func LoadFinger(t string) fingers.Fingers {
	fs, err := fingers.LoadFingers(LoadConfig(t))
	if err != nil {
		iutils.Fatal(err.Error())
	}
	return fs
}

func LoadHashFinger(fs fingers.Fingers) (map[string]string, map[string]string, []*fingers.Favicons) {
	md5hash := make(map[string]string)
	mmh3hash := make(map[string]string)
	var actives []*fingers.Favicons
	for _, f := range fs {
		for _, rule := range f.Rules {
			if rule.Favicon != nil {
				if rule.Favicon.Path != "" {
					actives = append(actives, rule.Favicon)
				}
				for _, mmh3 := range rule.Favicon.Mmh3 {
					mmh3hash[mmh3] = f.Name
				}
				for _, md5 := range rule.Favicon.Md5 {
					md5hash[md5] = f.Name
				}
			}
		}
	}
	return mmh3hash, md5hash, actives
}
