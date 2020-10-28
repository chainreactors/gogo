
gox.exe -osarch="linux/amd64 linux/386 windows/amd64 windows/386 darwin/amd64" -output=".\bin\getitle_{{.OS}}_{{.Arch}}%1" .\src\main\
upx ./bin/getitle_windows_386%1.exe
upx ./bin/getitle_windows_amd64%1.exe
tar cvf bin/getitle%1.zip bin/*