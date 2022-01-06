
## 配置指纹识别

指纹的json位于`src\Utils\finger.json`.

为了保证单文件可使用,将会在运行gox.bat时将json中的数据写到`src\Utils\finger.go`中

配置示例:

```
[    
	{
        "name": "Mysql_unauthorized",
        "level": 0,
        "defaultport": "3306",
        "regexps": [
            "Host .* is not allowed to connect to this MySQL server"
        ]
    }
]
```

`name`为规则名,string,请保证不重名

`level`为优先级,int,最高优先级为0

`defaultport`为该服务默认端口,string,用作提高匹配速度

`regexps`为正则列表,[]string, 默认为数组,同一规则可以配置多个正则依次匹配

### 注意事项

* json不接受`\x00`,`\0`等转义,请将类似转义修改成`\u0000`.

* 请注意数组元素间的逗号,否则可能导致json报错
