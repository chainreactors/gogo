import json
import sys,io
from base64 import b64encode

sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding='utf8')



if __name__ == "__main__":
	
	finger = open("src/Utils/finger.json","r",encoding="utf-8")
	jsonstr = finger.read()
	jsonstr = jsonstr.replace("\\0","\\u0000").replace("\\x","\\u00")
	j = json.loads(jsonstr)
	j = sorted(j,key=lambda x: x["level"])
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

