NOISECAT_BIN = noisecat
GOARCH = amd64

CURRENT_DIR=$(shell pwd)
NOISECAT_SRC=${CURRENT_DIR}/cmd/noisecat

TEST_DIR=${CURRENT_DIR}/pkg/noisecat
BIN_DIR=${CURRENT_DIR}/bin

LDFLAGS="-s -w"

# -- generic --
all: noisecat

noisecat: deps linux_noisecat darwin_noisecat windows_noisecat

linux: deps linux_noisecat
darwin: deps darwin_noisecat
windows: deps windows_noisecat
freebsd: deps freebsd_noisecat

test:
	cd ${TEST_DIR}; \
	go test -v
	cd ${CURRENT_DIR} >/dev/null

deps:
	go get -u -f github.com/gedigi/noisecat/...

# -- noisecat --
linux_noisecat: deps
	cd ${NOISECAT_SRC}; \
	GOOS=linux GOARCH=${GOARCH} go build -ldflags=${LDFLAGS} -o ${BIN_DIR}/${NOISECAT_BIN}-linux-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

darwin_noisecat: deps
	cd ${NOISECAT_SRC}; \
	GOOS=darwin GOARCH=${GOARCH} go build -ldflags=${LDFLAGS} -o ${BIN_DIR}/${NOISECAT_BIN}-darwin-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

windows_noisecat: deps
	cd ${NOISECAT_SRC}; \
	GOOS=windows GOARCH=${GOARCH} go build -ldflags=${LDFLAGS} -o ${BIN_DIR}/${NOISECAT_BIN}-windows-${GOARCH}.exe . ; \
	cd ${CURRENT_DIR} >/dev/null

freebsd_noisecat: deps
	cd ${NOISECAT_SRC}; \
	GOOS=freebsd GOARCH=${GOARCH} go build -ldflags=${LDFLAGS} -o ${BIN_DIR}/${NOISECAT_BIN}-freebsd-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

clean:
	-rm -rf ${BIN_DIR}

.PHONY: all clean deps linux darwin windows test clean noisecat
