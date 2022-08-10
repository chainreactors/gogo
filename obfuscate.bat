set name=gogo
set cert_domain=www.dbappsecurity.com.cn

@REM  go strip 去除编译信息
go-strip -f ./bin/%name%_windows_386.exe -a -output ./bin/%name%_windows_386.exe
go-strip -f ./bin/%name%_windows_amd64.exe -a -output ./bin/%name%_windows_amd64.exe
go-strip -f ./bin/%name%_linux_arm64 -a -output ./bin/%name%_linux_arm64
go-strip -f ./bin/%name%_linux_arm -a -output ./bin/%name%_linux_arm
go-strip -f ./bin/%name%_linux_amd64 -a -output ./bin/%name%_linux_amd64
go-strip -f ./bin/%name%_linux_386 -a -output ./bin/%name%_linux_386
go-strip -f ./bin/%name%_linux_mips64 -a -output ./bin/%name%_linux_mips64
go-strip -f ./bin/%name%_darwin_amd64 -a -output ./bin/%name%_darwin_amd64

@REM upx 加壳
upxs  -k -o ./bin/%name%_windows_386_upx.exe ./bin/%name%_windows_386.exe
upxs  -k -o ./bin/%name%_windows_amd64_upx.exe ./bin/%name%_windows_amd64.exe
upxs  ./bin/%name%_darwin_amd64
upxs  ./bin/%name%_linux_386
upxs  ./bin/%name%_linux_amd64
upxs  ./bin/%name%_linux_arm64
upxs  ./bin/%name%_linux_arm

@REM 伪造证书
limelighter -I ./bin/%name%_windows_amd64.exe -O ./bin/%name%_windows_amd64s.exe -Domain %cert_domain%
limelighter -I ./bin/%name%_windows_amd64_upx.exe -O ./bin/%name%_windows_amd64_upxs.exe -Domain %cert_domain%
limelighter -I ./bin/%name%_windows_386_upx.exe -O ./bin/%name%_windows_386_upxs.exe -Domain %cert_domain%
limelighter -I ./bin/%name%_windows_386.exe -O ./bin/%name%_windows_386s.exe -Domain %cert_domain%

rm ./bin/%name%_windows_amd64.exe
rm ./bin/%name%_windows_amd64_upx.exe
rm ./bin/%name%_windows_386.exe
rm ./bin/%name%_windows_386_upx.exe
