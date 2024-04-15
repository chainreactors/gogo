package pkg

import (
	"github.com/chainreactors/fingers/fingers"
)

var (
	FingerEngine *fingers.FingersRules
	//AllHttpFingers     fingers.Fingers
	//SocketFingers      fingers.FingerMapper
	//ActiveFavicons     []*fingers.Favicons
	//ActiveHttpFingers  fingers.Fingers
	//PassiveHttpFingers fingers.Fingers
)

// LoadFinger 加载指纹到全局变量
func LoadFinger() error {
	engine, err := fingers.NewFingersEngine(LoadConfig("http"), LoadConfig("tcp"))
	if err != nil {
		return err
	}
	FingerEngine = engine
	return nil
}

//func LoadHashFinger(fs fingers.Fingers) (map[string]string, map[string]string, []*fingers.Favicons) {
//	md5hash := make(map[string]string)
//	mmh3hash := make(map[string]string)
//	var actives []*fingers.Favicons
//	for _, f := range fs {
//		for _, rule := range f.Rules {
//			if rule.Favicon != nil {
//				if rule.Favicon.Path != "" {
//					actives = append(actives, rule.Favicon)
//				}
//				for _, mmh3 := range rule.Favicon.Mmh3 {
//					mmh3hash[mmh3] = f.Name
//				}
//				for _, md5 := range rule.Favicon.Md5 {
//					md5hash[md5] = f.Name
//				}
//			}
//		}
//	}
//	return mmh3hash, md5hash, actives
//}
