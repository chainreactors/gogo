python FingerprintUpdate.py

gox.exe -osarch="linux/amd64 linux/arm64 linux/386 windows/amd64 linux/mips64 windows/386 darwin/amd64" -ldflags="-s -w" -gcflags=-trimpath=$GOPATH;$GOROOT -asmflags=-trimpath=$GOPATH -output=".\bin\getitle_{{.OS}}_{{.Arch}}_v%1" .\src\main\

go-strip -f ./bin/getitle_windows_386_v%1.exe -a -output ./bin/getitle_windows_386_v%1.exe > nul
go-strip -f ./bin/getitle_windows_amd64_v%1.exe -a -output ./bin/getitle_windows_amd64_v%1.exe > nul
go-strip -f ./bin/getitle_linux_386_v%1 -a -output ./bin/getitle_linux_386_v%1 > nul
go-strip -f ./bin/getitle_linux_arm64_v%1 -a -output ./bin/getitle_linux_arm64_v%1 > nul
go-strip -f ./bin/getitle_linux_amd64_v%1 -a -output ./bin/getitle_linux_amd64_v%1 > nul
go-strip -f ./bin/getitle_linux_mips64_v%1 -a -output ./bin/getitle_linux_mips64_v%1 > nul
go-strip -f ./bin/getitle_darwin_amd64_v%1 -a -output ./bin/getitle_darwin_amd64_v%1 > nul



upxs -1 -k -o ./bin/getitle_windows_386_v%1_upx.exe ./bin/getitle_windows_386_v%1.exe
upxs -1 -k -o ./bin/getitle_windows_amd64_v%1_upx.exe ./bin/getitle_windows_amd64_v%1.exe
upxs -1 -k -o ./bin/getitle_linux_386_v%1_upx ./bin/getitle_linux_386_v%1
upxs -1 -k -o ./bin/getitle_linux_amd64_v%1_upx ./bin/getitle_linux_amd64_v%1
upxs -1 -k -o ./bin/getitle_linux_arm64_v%1_upx ./bin/getitle_linux_arm64_v%1
upxs -1 -k -o ./bin/getitle_darwin_amd64_v%1_upx ./bin/getitle_darwin_amd64_v%1

limelighter -I ./bin/getitle_windows_amd64_v%1.exe -O ./bin/getitle_windows_amd64_sangfor_v%1.exe -Domain www.sangfor.com
rm *.sangfor.*

tar cvf release/getitlev%1.tar bin/* README.md gtfilter.py