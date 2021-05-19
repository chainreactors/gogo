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
@click.option('--output','-o', help='filter rules')
def main(inputfile,outtype,fil,output):

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
    # f = open(sys.argv[1],"r",encoding="utf-8")
    # j = json.load(f)
    # p1 = sys.argv[2]
    # p2 = sys.argv[3]
    # need = sys.argv[4]
    # # res = list(filter(lambda x:p2 in x[p1],j))
    # print(len(j))
    # res = list(filter(lambda x:"" != x[p1],j))
    # res = list(filter(lambda x:x["protocol"].startswith("http") or x["framework"] != "",res))
    # res = list(filter(lambda x:"HTTP" not in x[p1],res))
    # print(len(res))
    # tmp = []
    # for i in res:
    #     for k in need.split(","):
    #         if k == "url":
    #             print(geturl(i))
    #         elif k == "target":
    #             print(gettarget(i))
    #         else:
    #             tmp.append(i[k])
    #
    # print(len(tmp))
    # for i in set(tmp):
    #     print(i)


    # print(",".join(res))

