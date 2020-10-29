
gox.exe -osarch="linux/amd64 linux/386 windows/amd64 windows/386 darwin/amd64" -output=".\bin\getitle_{{.OS}}_{{.Arch}}%1" .\src\main\
rem upx -9 ./bin/getitle_windows_386%1.exe
rem upx -9 ./bin/getitle_windows_amd64%1.exe
rem upx -9 ./bin/getitle_linux_386%1
rem upx -9 ./bin/getitle_linux_amd64%1
rem upx -9 ./bin/getitle_darwin_amd64%1
tar cvf release/getitle%1.zip bin/* README.md