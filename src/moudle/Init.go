package moudle

import (
	"fmt"
	"os"
	"strings"
	"time"
)


type Params struct {
	Ports     string
	Threads   int
	IPaddress string
	Mod       string
	Delay     time.Duration
}

func Init(initparams Params,key string) Params {
	fmt.Println("*********  getitle 0.1.2 beta by Sangfor  *********")

	if key != "sangfor" {
		println("FUCK OFF")
		os.Exit(0)
	}
	if initparams.IPaddress == "" {
		Banner()
		os.Exit(0)
	} else if !strings.Contains(initparams.IPaddress,"/") {
		initparams.IPaddress += "/32"
	}

	switch initparams.Ports {
	case "top1":
		initparams.Ports = "80,443,8080,7001,9001,8081,8082,8089,8000,8443,81"
	case "top2":
		initparams.Ports = "80-89,443,7000-7009,9000-9009,8080-8090,8000-8009,8443,7080,8070,9080,8888,7777,9090,800,801,9999,10080"
	case "db":
		initparams.Ports = "3306,1433,1521,5432,6379,11211,27017"
	case "rce":
		initparams.Ports = "1090,1098,1099,4444,11099,47001,47002,10999,45000,45001,8686,9012,50500,4848,11111,4445,4786,5555,5556"
	case "win":
		initparams.Ports = "53,88,135,139,389,445,3389,5985"
	case "brute":
		initparams.Ports = "21,22,389,445,1433,1521,3306,3389,5901,5432,6379,11211,27017"
	case "all":
		initparams.Ports = "21,22,23,25,53,69,80-89,110,135,139,143,443,445,465,993,995,1080,1158,1433,1521,1863,2100,3128,3306,3389,7001,8080-8089,8888,9080,9090,5900,1090,1099,7002,8161,9043,50000,50070,389,5432,5984,9200,11211,27017,161,873,1833,2049,2181,2375,6000,6666,6667,7777,6868,9000,9001,12345,5632,9081,3700,4848,1352,8069,9300"

	default:

	}
	return initparams
}
