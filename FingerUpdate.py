import json
import sys,io
from base64 import b64encode

sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding='utf8')


finger = open("src/Utils/finger.json","r",encoding="utf-8")
jsonstr = finger.read()
jsonstr = jsonstr.replace("\\0","\\u0000").replace("\\x","\\u00")
j = json.loads(jsonstr)

f = open("src/Utils/finger.go","w",encoding="utf-8")
base = '''package Utils

func loadFingers()string  {
	return `
%s
`
}
'''
f.write(base%json.dumps(j))
print("finger update success")

