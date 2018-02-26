# Simple make utilities for common tasks.

build:
	go build

test:
	go test -v ./...

release:
	env GOOS=linux GOARCH=amd64 go build -o bin/linux/amd64/ring-signatures
	env GOOS=darwin GOARCH=amd64 go build -o bin/darwin/amd64/ring-signatures
	env GOOS=windows GOARCH=amd64 go build -o bin/windows/amd64/ring-signatures.exe