set name=getitle
set cert_domain=www.dbappsecurity.com.cn
rm ./bin/*
go generate getitle.go
gox.exe -osarch="linux/amd64 linux/arm64 linux/386 windows/amd64 linux/mips64 windows/386 darwin/amd64" -ldflags="-s -w -X 'getitle/v1/cmd.ver=v%1' -X 'getitle/v1/cmd.k=%2'" -gcflags="-trimpath=$GOPATH" -asmflags="-trimpath=$GOPATH" -output=".\bin\%name%_{{.OS}}_{{.Arch}}" .
echo off
@REM  go strip 去除编译信息
go-strip -f ./bin/%name%_windows_386.exe -a -output ./bin/%name%_windows_386.exe
go-strip -f ./bin/%name%_windows_amd64.exe -a -output ./bin/%name%_windows_amd64.exe
go-strip -f ./bin/%name%_linux_386 -a -output ./bin/%name%_linux_386
go-strip -f ./bin/%name%_linux_arm64 -a -output ./bin/%name%_linux_arm64
go-strip -f ./bin/%name%_linux_amd64 -a -output ./bin/%name%_linux_amd64
go-strip -f ./bin/%name%_linux_mips64 -a -output ./bin/%name%_linux_mips64
go-strip -f ./bin/%name%_darwin_amd64 -a -output ./bin/%name%_darwin_amd64
echo on

@REM upx 加壳
upxs  -k -o ./bin/%name%_windows_386_upx.exe ./bin/%name%_windows_386.exe
upxs  -k -o ./bin/%name%_windows_amd64_upx.exe ./bin/%name%_windows_amd64.exe
upxs  ./bin/%name%_darwin_amd64
upxs  ./bin/%name%_linux_386
upxs  ./bin/%name%_linux_amd64
upxs  ./bin/%name%_linux_arm64

@REM 伪造证书
limelighter -I ./bin/%name%_windows_amd64.exe -O ./bin/%name%_windows_amd64s.exe -Domain %cert_domain%
limelighter -I ./bin/%name%_windows_amd64_upx.exe -O ./bin/%name%_windows_amd64_upxs.exe -Domain %cert_domain%
limelighter -I ./bin/%name%_windows_386_upx.exe -O ./bin/%name%_windows_386_upxs.exe -Domain %cert_domain%
limelighter -I ./bin/%name%_windows_386.exe -O ./bin/%name%_windows_386s.exe -Domain %cert_domain%

rm ./bin/%name%_windows_amd64.exe
rm ./bin/%name%_windows_amd64_upx.exe
rm ./bin/%name%_windows_386.exe
rm ./bin/%name%_windows_386_upx.exe

@REM 上传到阿里云

ossutil cp ./bin/%name%_windows_386_upxs.exe oss://sangfor-release/fscan/windows_386_upxs.exe -f
ossutil cp ./bin/%name%_windows_386s.exe oss://sangfor-release/fscan/windows_386s.exe -f
ossutil cp ./bin/%name%_windows_amd64s.exe oss://sangfor-release/fscan/windows_amd64s.exe -f
ossutil cp ./bin/%name%_windows_amd64_upxs.exe  oss://sangfor-release/fscan/windows_amd64_upxs.exe -f
ossutil cp ./bin/%name%_linux_386 oss://sangfor-release/fscan/linux_386 -f
ossutil cp ./bin/%name%_linux_arm64  oss://sangfor-release/fscan/linux_arm64 -f
ossutil cp ./bin/%name%_linux_amd64 oss://sangfor-release/fscan/linux_amd64 -f
ossutil cp ./bin/%name%_linux_mips64 oss://sangfor-release/fscan/linux_mips64 -f
ossutil cp ./bin/%name%_darwin_amd64 oss://sangfor-release/fscan/darwin_amd64 -f

@REM 打包
tar -zcvf release/%name%v%1.tar.gz bin/%name%* doc/* README.md *.py UPDATELOG.md