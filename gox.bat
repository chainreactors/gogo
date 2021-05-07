python FingerprintUpdate.py

go env -w GOFLAGS="-trimpath"
gox.exe -osarch="linux/amd64 linux/arm64 linux/386 windows/amd64 windows/386 darwin/amd64" -ldflags="-s -w" -output=".\bin\getitle_{{.OS}}_{{.Arch}}_v%1" .\src\main\
go env -w GOFLAGS=""

upx -1 -k -o ./bin/getitle_windows_386_v%1_upx.exe ./bin/getitle_windows_386_v%1.exe
upx -1 -k -o ./bin/getitle_windows_amd64_v%1_upx.exe ./bin/getitle_windows_amd64_v%1.exe
upx -1 -k -o ./bin/getitle_linux_386_v%1_upx ./bin/getitle_linux_386_v%1
upx -1 -k -o ./bin/getitle_linux_amd64_v%1_upx ./bin/getitle_linux_amd64_v%1
upx -1 -k -o ./bin/getitle_linux_arm64_v%1_upx ./bin/getitle_linux_arm64_v%1
upx -1 -k -o ./bin/getitle_darwin_amd64_v%1_upx ./bin/getitle_darwin_amd64_v%1

limelighter -I ./bin/getitle_windows_amd64_v%1.exe -O ./bin/getitle_windows_amd64_sangfor_v%1.exe -Domain www.sangfor.com
rm *.sangfor.*

tar cvf release/getitlev%1.tar bin/* README.md