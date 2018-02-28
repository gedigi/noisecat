BINARY = noisecat
GOARCH = amd64

CURRENT_DIR=$(shell pwd)
SOURCE_DIR=${CURRENT_DIR}/src
BIN_DIR=${CURRENT_DIR}/bin

# Build the project
all: linux darwin windows

deps:
	go get github.com/gedigi/noisecat/...

linux: deps
	cd ${SOURCE_DIR}; \
	GOOS=linux GOARCH=${GOARCH} go build -o ${CURRENT_DIR}/${BINARY}-linux-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

darwin: deps
	cd ${SOURCE_DIR}; \
	GOOS=darwin GOARCH=${GOARCH} go build -o ${CURRENT_DIR}/${BINARY}-darwin-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

windows: deps
	cd ${SOURCE_DIR}; \
	GOOS=windows GOARCH=${GOARCH} go build -o ${CURRENT_DIR}/${BINARY}-windows-${GOARCH}.exe . ; \
	cd ${CURRENT_DIR} >/dev/null

test:
	cd ${SOURCE_DIR}; \
	go test -v
	cd ${CURRENT_DIR} >/dev/null

clean:
	-rm -f ${BINARY}-*

.PHONY: deps linux darwin windows test clean
