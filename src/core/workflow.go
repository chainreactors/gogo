package core

var InterConfig = map[string][]string{
	"10.0.0.0/8":     {"ss", "icmp", "1"},
	"172.16.0.0/12":  {"ss", "icmp", "1"},
	"192.168.0.0/16": {"s", "80", "all"},
	"100.100.0.0/16": {"s", "icmp", "all"},
	"200.200.0.0/16": {"s", "icmp", "all"},
	//"169.254.0.0/16": {"s", "icmp", "all"},
	//"168.254.0.0/16": {"s", "icmp", "all"},
}

type WorkFlow struct {
	Name       string `json:"name"`
	IP         string `json:"ip"`
	Ports      string `json:"ports"`
	Mod        string `json:"mod"`
	Ping       bool   `json:"ping"`
	Arp        bool   `json:"arp"`
	NoScan     bool   `json:"no"`
	IpProbe    string `json:"ipp"`
	SmartProbe string `json:"sp"`
	File       string `json:"file"`
}
