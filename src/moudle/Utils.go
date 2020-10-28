package moudle

import (
	"strconv"
	"strings"
)


func Ports2Portlist(ports string) []string {
	var portlist []string

	rawportlist := strings.Split(ports, ",")

	//生成端口列表 支持,和-
	for i := 0; i < len(rawportlist); i++ {
		if strings.Index(rawportlist[i], "-") > 0 {
			//fmt.Println(rawportlist[i])
			sf := strings.Split(rawportlist[i], "-")
			start, _ := strconv.Atoi(sf[0])

			fin, _ := strconv.Atoi(sf[1])

			for j := start; j <= fin; j++ {
				cur := strconv.Itoa(j)
				portlist = append(portlist, cur)
			}
		} else {
			portlist = append(portlist, rawportlist[i])
		}
	}
	return portlist

}