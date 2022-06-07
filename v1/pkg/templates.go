package pkg

var RandomDir = "/g8kZMwp4oeKsL2in"

func LoadConfig(typ string)[]byte  {
	if typ == "tcp" {
		return Decode("")
	}else if typ=="http"{
		return Decode("")
	}else if typ =="md5"{
		return Decode("")
	}else if typ == "mmh3"{
		return Decode("")
	}else if typ =="port"{
		return Decode("")
	}else if typ == "workflow"{
		return Decode("")
	}else if typ == "nuclei"{
		return Decode("")
	}
	return []byte{}
}