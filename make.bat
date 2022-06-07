set name=getitle
rm ./bin/*
go generate getitle.go
gox.exe -osarch="linux/amd64 linux/arm64 linux/386 windows/amd64 linux/mips64 windows/386 darwin/amd64" -ldflags="-s -w -X 'getitle/v1/cmd.ver=v%1' -X 'getitle/v1/cmd.k=%2'" -gcflags="-trimpath=$GOPATH" -asmflags="-trimpath=$GOPATH" -output=".\bin\%name%_{{.OS}}_{{.Arch}}" .

