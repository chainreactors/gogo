package Utils

func loadFingers() string {
	return `
	[{"name": "MariaDB_unauthorized", "level": 0, "defaultport": "3306", "regexps": ["Host .* is not allowed to connect to this MariaDB server"]}, {"name": "MariaDB", "level": 0, "defaultport": "3306", "regexps": ["^.\u0000\u0000\u0000\n(5\\.[-_~.+:\\w]+MariaDB-[-_~.+:\\w]+)\u0000"]}]
	`
}
