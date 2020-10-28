# Binary name
BINARY= getitle
# Builds the project
build:
		go build -o ${BINARY} ./src/main/main.go
# Installs our project: copies binaries
install:
		go install
release:
		# Clean
		#go clean
		rm -rf *.gz
		# Build for mac
		go build -o ./bin/getitle-mac64-${VERSION} ./src/main/main.go
		#tar czvf ./bingetitle-mac64-${VERSION}.tar.gz ./bin/getitle-mac64-${VERSION}
		# Build for linux
		#go clean
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/getitle-linux64-${VERSION} ./src/main/main.go
		#tar czvf ./bin/getitle-linux64-${VERSION}.tar.gz ./getitle-linux64-${VERSION}
		#go clean
		CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -o ./bin/getitle-linux32-${VERSION} ./src/main/main.go
		#tar czvf ./bin/getitle-linux32-${VERSION}.tar.gz ./bin/getitle-linux32-${VERSION}
		# Build for win
		#go clean
		CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ./bin/getitle-win64-${VERSION}.exe  ./src/main/main.go
		#upx ./bin/getitle-win64-${VERSION}.exe
		#go clean
		CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -o ./bin/getitle-win32-${VERSION}.exe ./src/main/main.go
		#upx ./bin/getitle-win32-${VERSION}.exe
		#go clean
# Cleans our projects: deletes binaries
clean:
		go clean

.PHONY:  clean build