package Utils

// common struct

type Finger struct {
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"`
	SendData    string   `json:"send_data"`
	Vuln        string   `json:"vuln"`
	Level       int      `json:"level"`
	Defaultport []string `json:"default_port"`
	Regexps     Regexps  `json:"regexps"`
}

type Regexps struct {
	HTML   []string `json:"html"`
	MD5    []string `json:"md5"`
	Regexp []string `json:"regexp"`
	Cookie []string `json:"cookie"`
	Header []string `json:"header"`
	Vuln   []string `json:"vuln"`
}

type PortFinger struct {
	Name  string   `json:"name"`
	Ports []string `json:"ports"`
	Type  []string `json:"type"`
}
