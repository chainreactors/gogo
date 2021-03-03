import json
import sys,io
from base64 import b64encode

sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding='utf8')



def fingerload(filename):
    tcpfinger = open("src/Utils/%s"%filename,"r",encoding="utf-8")
    tcpjsonstr = tcpfinger.read()
    tcpjsonstr = tcpjsonstr.replace("\\0","\\u0000").replace("\\x","\\u00")
    j = json.loads(tcpjsonstr)
    j = sorted(j,key=lambda x: x["level"])
    return j


if __name__ == "__main__":
	j1 = fingerload("tcpfingers.json")
	j2 = fingerload("httpfingers.json")
	j3 = json.loads(open("src/Utils/md5fingers.json","r",encoding="utf-8").read())
	f = open("src/Utils/finger.go","w",encoding="utf-8")
	base = '''package Utils

func LoadFingers(typ string)string  {
	if typ == "tcp" {
		return `
		%s
	`
	}else if typ=="http"{
		return `
		%s
	`
	}else if typ =="md5"{
     		return `
     		%s
     		`
    }
	return  ""
}
	'''

	f.write(base%(json.dumps(j1),json.dumps(j2),json.dumps(j3)))
	print("fingerprint update success")

