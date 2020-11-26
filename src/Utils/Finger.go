package Utils

import (
	"encoding/json"
	"os"
)

func GetFinger() []Finger {
	fingerdata := `
[{"name": "Mysql_unauthorized", "level": 0, "version": false, "regexps": ["Host .* is not allowed to connect to this MySQL server"]}, {"name": "MariaDB_unauthorized", "level": 0, "version": false, "regexps": ["Host .* is not allowed to connect to this MariaDB server"]}, {"name": "MySQL", "level": 0, "version": true, "regexps": ["^.\u0000\u0000\u0000\n(.\\.[-_~.+\\w]+)\u0000", "Host .* is blocked because of many connection errors", "^.\u0000\u0000\u0000\u00ffj\u0004'[\\d.]+' .* MySQL"]}, {"name": "MariaDB", "level": 0, "version": true, "regexps": ["^.\u0000\u0000\u0000\n(5\\.[-_~.+:\\w]+MariaDB-[-_~.+:\\w]+)\u0000"]}]
`

	var fingers []Finger
	err := json.Unmarshal([]byte(fingerdata), &fingers)
	if err != nil {
		println("[-] fingers load FAIL!")
		os.Exit(0)
	}
	return fingers
}
