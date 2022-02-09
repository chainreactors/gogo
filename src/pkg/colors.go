package pkg

func Red(s string) string {
	return "\033[1;31m" + s + "\033[0m"
}

func Green(s string) string {
	return "\033[1;32m" + s + "\033[0m"
}

func Yellow(s string) string {
	return "\033[4;33m" + s + "\033[0m"
}

func Blue(s string) string {
	return "\033[1;34m" + s + "\033[0m"
}
