import json, yaml
import sys, io, os, zlib
from base64 import b64encode
import random

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


def yaml2json(content, com=True):
    y = yaml.load(content)
    if com:
        return compress(json.dumps(y))
    else:
        return json.dumps(y)


def json2yaml(content):
    j = json.loads(content)
    return yaml.dump(content)


def read(filename):
    with open("src/config/"+filename, "r", encoding="utf-8") as f:
        return f.read()



if __name__ == "__main__":
    tcpfingers = read("tcpfingers.yaml")
    httpfingers = read("httpfingers.yaml")
    md5fingers = read("md5fingers.yaml")

    port = read("port.yaml")
    mmh3fingers = read("mmh3fingers.yaml")
    workflows = read("workflows.yaml")
    nuclei = loadnuclei()
    f = open("src/utils/finger.go", "w", encoding="utf-8")
    base = '''package utils

var RandomDir = "/%s"

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
    }else if typ == "workflow"{
         	return Decode(`%s`)
    }else if typ == "nuclei"{
            return Decode(`%s`)
    }
	return []byte{}
}
	'''
#     print(yaml2json(tcpfingers))
    f.write(base % (''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 16)),
                    yaml2json(tcpfingers),
                    yaml2json(httpfingers),
                    yaml2json(md5fingers),
                    yaml2json(port),
                    yaml2json(mmh3fingers),
                    yaml2json(workflows),
                    compress(json.dumps(nuclei))))
#     print(compress(json.dumps(tcpfingers)))
    print("fingerprint update success")

