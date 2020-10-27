# Binary name
BINARY= getitle
# Builds the project
build:
		go build -o ${BINARY}
		go test -v
# Installs our project: copies binaries
install:
		go install
release:
		# Clean
		go clean
		rm -rf *.gz
		# Build for mac
		go build -o getitle-mac64-${VERSION}
		tar czvf getitle-mac64-${VERSION}.tar.gz ./getitle-mac64-${VERSION}
		# Build for linux
		go clean
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o getitle-linux64-${VERSION}
		tar czvf getitle-linux64-${VERSION}.tar.gz ./getitle-linux64-${VERSION}
		go clean
		CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -o getitle-linux32-${VERSION}
		tar czvf getitle-linux32-${VERSION}.tar.gz ./getitle-linux32-${VERSION}
		# Build for win
		go clean
		CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o getitle-win64-${VERSION}.exe
		tar czvf getitle-win64-${VERSION}.tar.gz ./getitle-win64-${VERSION}.exe
		go clean
		CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -o getitle-win32-${VERSION}.exe
		tar czvf getitle-win32-${VERSION}.tar.gz ./getitle-win32-${VERSION}.exe
		go clean
# Cleans our projects: deletes binaries
clean:
		go clean

.PHONY:  clean build