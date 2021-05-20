# -*- coding: utf-8 -*-
import json
import sys
import click

def geturl(i):
    return "%s://%s:%s"%(i["protocol"],i["ip"],i["port"])

def gettarget(i):
    return "%s:%s"%(i["ip"],i["port"])

def tores(js,typ):
    if typ == "url":
        return geturl(js)
    elif typ == "target":
        return gettarget(js)
    elif typ == "ip":
        return js["ip"]


@click.command()
@click.argument("inputfile",type=click.File("r",encoding="utf-8"))
@click.option('--outtype','-t', default="target", help='Output format.')
@click.option('--fil','-f',multiple=True, help='filter rules')
@click.option('--output','-o', help='output file')
def main(inputfile,outtype,fil,output):
    """    使用帮助:                      
    
    \b
    过滤规则-f e.g:
    全等匹配: port=443
    模糊匹配: title:系统 
    排除: protocol!tcp 
    允许使用多个filter器,例如 -f port=443 -f title:系统

    \b
    输出规则-t ,当前有三种类型输出: ip(默认值),url,target    e.g:
    ip: 192.168.1.1  [ip]
    target: 192.168.1.1:445 [ip]:[port]
    url: http://192.168.1.1:8080 [protocol]://[ip]:[port]

    \b
    输出到文件-o: e.g: -o res.txt, 如果不指定-o则输出到命令行

    \b
    example: 
    # 输出端口为443的ip 
    python gtfilter.py input.json -f port=443  
    \b
    # 输出端口为443的target结果
    python gtfilter.py input.json -f port=443 -t target 
    \b
    # 输出端口为443,title中包含系统的url到命令行
    python gtfilter.py input.json -f port=443 -f title:系统 -t url 
    \b
    # 与上相同,结果输出到res.txt文件
    python gtfilter.py input.json -f port=443 -f title:系统 -t target -o res.txt 


    """
    j = json.load(inputfile)
    for f in fil:
        if "=" in f:
            source,sink = f.split("=")
            j = list(filter(lambda x: x[source] == sink, j))

        elif ":" in f:
            source,sink = f.split(":")
            j = list(filter(lambda x: sink in x[source], j))

        elif "!" in f:
            source,sink = f.split("!")
            j = list(filter(lambda x: sink not in x[source], j))

    if output != None:
        file = open(output,"a")
        for line in j:
            file.write(tores(line,outtype) + "\n")
        file.close()
    else:
        for line in j:
            print(tores(line,outtype))




if __name__ == '__main__':
    main()
   

