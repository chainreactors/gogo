import json
import sys,io
from base64 import b64encode

sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding='utf8')



def fingerload(filename):
    tcpfinger = open("src/config/%s"%filename,"r",encoding="utf-8")
    tcpjsonstr = tcpfinger.read()
    tcpjsonstr = tcpjsonstr.replace("\\0","\\u0000").replace("\\x","\\u00")
    j = json.loads(tcpjsonstr)
    j = sorted(j,key=lambda x: x["level"])
    return j


if __name__ == "__main__":
	tcpfingers = fingerload("tcpfingers.json")
	httpfingers = fingerload("httpfingers.json")
	md5fingers = json.loads(open("src/config/md5fingers.json","r",encoding="utf-8").read())
	port = json.loads(open("src/config/port.json","r",encoding="utf-8").read())
	mmh3fingers = json.loads(open("src/config/mmh3fingers.json","r",encoding="utf-8").read())
    nuclei = json.loads(open("src/config/nucleis.json","r",encoding="utf-8".read()
	f = open("src/Utils/finger.go","w",encoding="utf-8")
	base = '''package Utils

func LoadFingers(typ string)string  {
	if typ == "tcp" {
		return `%s`
	}else if typ=="http"{
		return `%s`
	}else if typ =="md5"{
     		return `%s`
    }else if typ == "port"{
         	return `%s`
    }else if typ =="mmh3"{
         	return `%s`
    }else if typ == "nuclei"{
         	return `%s`
     	}
	return  ""
}
	'''

	f.write(base%(json.dumps(tcpfingers),json.dumps(httpfingers),json.dumps(md5fingers),json.dumps(port),json.dumps(mmh3fingers),json.jump(j6)
	print("fingerprint update success")

