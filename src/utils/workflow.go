package utils

type WorkFlow struct {
	Name       string   `json:"name"`
	IP         string   `json:"ip"`
	Ports      string   `json:"ports"`
	Mod        string   `json:"mod"`
	Ping       bool     `json:"ping"`
	Arp        bool     `json:"arp"`
	NoScan     bool     `json:"no"`
	IpProbe    string   `json:"ipprobe"   default:"default"`
	SmartProbe string   `json:"portprobe" default:"default"`
	File       string   `json:"file" default:"-auto"`
	Tags       []string `json:"tags"`
}

func (w *WorkFlow) PrepareConfig() *Config {
	var config = &Config{
		IP:        w.IP,
		Ports:     w.Ports,
		Mod:       w.Mod,
		IpProbe:   w.IpProbe,
		SmartPort: w.SmartProbe,
	}
	if w.IpProbe == "" {
		w.IpProbe = "default"
	}
	if w.SmartProbe == "" {
		w.SmartProbe = "default"
	}
	if w.Arp {
		config.AliveSprayMod = append(config.AliveSprayMod, "arp")
	}
	if w.Ping {
		config.AliveSprayMod = append(config.AliveSprayMod, "icmp")
	}

	if w.File == "" {
		config.Filename = GetFilename(config, true, false, "", "json")
		if config.IsSmartScan() && !w.NoScan {
			config.SmartFilename = GetFilename(config, true, false, "", "cidr")
		}
		if config.HasAlivedScan() {
			config.PingFilename = GetFilename(config, true, false, "", "alived")
		}
	} else {
		config.Filename = w.File
	}

	return config
}
