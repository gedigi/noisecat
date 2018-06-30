NOISECAT_BIN = noisecat
NOISESOCAT_BIN = noisesocat
GOARCH = amd64

CURRENT_DIR=$(shell pwd)
NOISECAT_SRC=${CURRENT_DIR}/cmd/noisecat
NOISESOCAT_SRC=${CURRENT_DIR}/cmd/noisesocat

TEST_DIR=${CURRENT_DIR}/pkg/noisecat
BIN_DIR=${CURRENT_DIR}/bin

LDFLAGS="-s -w"

# -- generic --
all: noisecat noisesocat

noisecat: deps linux_noisecat darwin_noisecat windows_noisecat
noisesocat: deps linux_noisesocat darwin_noisesocat windows_noisesocat

linux: deps linux_noisecat linux_noisesocat
darwin: deps darwin_noisecat darwin_noisesocat
windows: deps windows_noisecat windows_noisesocat
freebsd: deps freebsd_noisecat freebsd_noisesocat

test:
	cd ${TEST_DIR}; \
	go test -v
	cd ${CURRENT_DIR} >/dev/null

deps:
	go get -u -f github.com/gedigi/noisecat/...
	go get -u -f github.com/gedigi/noise/...
	go get -u -f github.com/gedigi/noisesocket/...

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

# -- noisesocat --
linux_noisesocat: deps
	cd ${NOISESOCAT_SRC}; \
	GOOS=linux GOARCH=${GOARCH} go build -ldflags=${LDFLAGS} -o ${BIN_DIR}/${NOISESOCAT_BIN}-linux-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

darwin_noisesocat: deps
	cd ${NOISESOCAT_SRC}; \
	GOOS=darwin GOARCH=${GOARCH} go build -ldflags=${LDFLAGS} -o ${BIN_DIR}/${NOISESOCAT_BIN}-darwin-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

windows_noisesocat: deps
	cd ${NOISESOCAT_SRC}; \
	GOOS=windows GOARCH=${GOARCH} go build -ldflags=${LDFLAGS} -o ${BIN_DIR}/${NOISESOCAT_BIN}-windows-${GOARCH}.exe . ; \
	cd ${CURRENT_DIR} >/dev/null

freebsd_noisesocat: deps
	cd ${NOISESOCAT_SRC}; \
	GOOS=freebsd GOARCH=${GOARCH} go build -ldflags=${LDFLAGS} -o ${BIN_DIR}/${NOISESOCAT_BIN}-freebsd-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

clean:
	-rm -rf ${BIN_DIR}

.PHONY: all clean deps linux darwin windows test clean noisecat noisesocat
