# Getitle
just a weak scanner


## Usage

```
  example ./getitle -ip 192.168.92.1 -p top2
  -d int			超时,默认2s (default 2)  
  -ip string		IP地址 like 192.168.1.1/24
  -m string        扫描模式：straight or smartB (default "straight")
  -p string        ports (default "top1")
     ports preset:   top1(default) 80,81,88,443,8080,7001,9001,8081,8000,8443
                     top2 80-90,443,7000-7009,9000-9009,8080-8090,8000-8009,8443,7080,8070,9080,8888,7777,9999,9090,800,801,808,5555,10080
                     db 3306,1433,1521,5432,6379,11211,27017
                     rce 1090,1098,1099,4444,11099,47001,47002,10999,45000,45001,8686,9012,50500,4848,11111,4445,4786,5555,5556
                     win 53,88,135,139,389,445,3389,5985
                     all 21,22,23,25,53,69,80,81-89,110,135,139,143,443,445,465,993,995,1080,1158,1433,1521,1863,2100,3128,3306,3389,7001,8080,8081-8088,8888,9080,9090,5900,1090,1099,7002,8161,9043,50000,50070,389,5432,5984,9200,11211,27017,161,873,1833,2049,2181,2375,6000,6666,6667,7777,6868,9000,9001,12345,5632,9081,3700,4848,1352,8069,9300
  -t int        threads (default 4000)
```



## Makefile

 * make release VERSION=VERSION to bulid getitle to all platform

 * Windows build muli releases

   ```
   go get github.com/mitchellh/gox
   gox.bat
   ```

   

## Change Note

* v0.0.1 just a demo
* v0.0.3 
  * 获取不到getitile的情况下输出前13位字符(如果是http正好到状态码)
* v0.0.4 
  * 添加了端口预设top1为最常见的http端口,top2为常见的http端口,db为常见数据库默认端口,win为windows常见开放的端口
  * 简化了端口参数
* v0.0.5 
  * 修复了400与30x页面无法获取titile的问题
  * 修复了无法自定义端口的bug
  * 添加了brute与all两个端口预设,brute为可爆破端口,all为常见端口