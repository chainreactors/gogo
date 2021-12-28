import json, yaml
import sys, io, os, zlib
from base64 import b64encode

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf8')


def compress(s):
    flatedict = bytes(', ":'.encode())
    com = zlib.compressobj(level=9, zdict=flatedict)
    return b64encode(zlib.compress(s.encode())[2:-4]).decode()


def loadnuclei():
    pocs = []
    for root, _, files in os.walk("src/config/nuclei"):
        for file in files:
            pocs.append(yaml.load(open(os.path.join(root, file), encoding="utf-8")))
    return pocs


def fingerload(filename):
    tcpfinger = open("src/config/%s" % filename, "r", encoding="utf-8")
    tcpjsonstr = tcpfinger.read()
    tcpjsonstr = tcpjsonstr.replace("\\0", "\\u0000").replace("\\x", "\\u00")
    j = json.loads(tcpjsonstr)
    j = sorted(j, key=lambda x: x["level"])
    return j


if __name__ == "__main__":
    tcpfingers = fingerload("tcpfingers.json")
    httpfingers = fingerload("httpfingers.json")
    md5fingers = json.loads(open("src/config/md5fingers.json", "r", encoding="utf-8").read())
    port = json.loads(open("src/config/port.json", "r", encoding="utf-8").read())
    mmh3fingers = json.loads(open("src/config/mmh3fingers.json", "r", encoding="utf-8").read())
    nuclei = loadnuclei()
    f = open("src/utils/finger.go", "w", encoding="utf-8")
    base = '''package utils

func LoadConfig(typ string)[]byte  {
	if typ == "tcp" {
		return Decode(`%s`)
	}else if typ=="http"{
		return Decode(`%s`)
	}else if typ =="md5"{
     		return Decode(`%s`)
    }else if typ == "port"{
         	return Decode(`%s`)
    }else if typ =="mmh3"{
         	return Decode(`%s`)
    }else if typ == "nuclei"{
         	return Decode(`%s`)
     	}
	return []byte{}
}
	'''

    f.write(base % (compress(json.dumps(tcpfingers)),
                    compress(json.dumps(httpfingers)),
                    compress(json.dumps(md5fingers)),
                    compress(json.dumps(port)),
                    compress(json.dumps(mmh3fingers)),
                    compress(json.dumps(nuclei))))
#     print(compress(json.dumps(tcpfingers)))
    print("fingerprint update success")

