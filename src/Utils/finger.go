package Utils

import (
	"encoding/json"
	"os"
)

func GetFinger() []Finger {
	fingerdata := `
[{"name": "Mysql_unauthorized", "level": 1, "defaultport": "3306", "regexps": ["Host .* is not allowed to connect to this MySQL server"]}, {"name": "MariaDB_unauthorized", "level": 1, "defaultport": "3306", "regexps": ["Host .* is not allowed to connect to this MariaDB server"]}, {"name": "MySQL", "level": 0, "defaultport": "3306", "regexps": ["^.\u0000\u0000\u0000\n(.\\.[-_~.+\\w]+)\u0000", "Host .* is blocked because of many connection errors", "^.\u0000\u0000\u0000\u00ffj\u0004'[\\d.]+' .* MySQL"]}, {"name": "MariaDB", "level": 0, "defaultport": "3306", "regexps": ["^.\u0000\u0000\u0000\n(5\\.[-_~.+:\\w]+MariaDB-[-_~.+:\\w]+)\u0000"]}]
`

	var fingers []Finger
	err := json.Unmarshal([]byte(fingerdata), &fingers)
	if err != nil {
		println("[-] fingers load FAIL!")
		os.Exit(0)
	}
	return fingers
}

// 通过默认端口加快匹配速度
func fingerSplit(port string) ([]Finger, []Finger) {
	var defaultportFingers, otherportFingers []Finger
	for _, finger := range fingers {
		if finger.Defaultport == port {
			defaultportFingers = append(defaultportFingers, finger)
		} else {
			otherportFingers = append(otherportFingers, finger)
		}
	}
	return defaultportFingers, otherportFingers
}
