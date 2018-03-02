NOISECAT_BIN = noisecat
NOISESOCAT_BIN = noisesocat
GOARCH = amd64

CURRENT_DIR=$(shell pwd)
NOISECAT_SRC=${CURRENT_DIR}/cmd/noisecat
NOISESOCAT_SRC=${CURRENT_DIR}/cmd/noisesocat

NOISECAT_TEST=${CURRENT_DIR}/pkg/noisecat
NOISESOCAT_TEST=${CURRENT_DIR}/pkg/noisesocat

# -- generic --
all: test noisecat noisesocat

test: test_noisecat test_noisesocat
noisecat: deps linux_noisecat darwin_noisecat windows_noisecat
noisesocat: deps linux_noisesocat darwin_noisesocat windows_noisesocat

deps:
	go get github.com/gedigi/noisecat/...

# -- noisecat --
linux_noisecat: deps
	cd ${NOISECAT_SRC}; \
	GOOS=linux GOARCH=${GOARCH} go build -o ${CURRENT_DIR}/${NOISECAT_BIN}-linux-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

darwin_noisecat: deps
	cd ${NOISECAT_SRC}; \
	GOOS=darwin GOARCH=${GOARCH} go build -o ${CURRENT_DIR}/${NOISECAT_BIN}-darwin-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

windows_noisecat: deps
	cd ${NOISECAT_SRC}; \
	GOOS=windows GOARCH=${GOARCH} go build -o ${CURRENT_DIR}/${NOISECAT_BIN}-windows-${GOARCH}.exe . ; \
	cd ${CURRENT_DIR} >/dev/null

test_noisecat:
	cd ${NOISECAT_TEST}; \
	go test -v
	cd ${CURRENT_DIR} >/dev/null

# -- noisesocat --
linux_noisesocat: deps
	cd ${NOISESOCAT_SRC}; \
	GOOS=linux GOARCH=${GOARCH} go build -o ${CURRENT_DIR}/${NOISESOCAT_BIN}-linux-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

darwin_noisesocat: deps
	cd ${NOISESOCAT_SRC}; \
	GOOS=darwin GOARCH=${GOARCH} go build -o ${CURRENT_DIR}/${NOISESOCAT_BIN}-darwin-${GOARCH} . ; \
	cd ${CURRENT_DIR} >/dev/null

windows_noisesocat: deps
	cd ${NOISESOCAT_SRC}; \
	GOOS=windows GOARCH=${GOARCH} go build -o ${CURRENT_DIR}/${NOISESOCAT_BIN}-windows-${GOARCH}.exe . ; \
	cd ${CURRENT_DIR} >/dev/null

test_noisesocat:
	cd ${NOISESOCAT_TEST}; \
	go test -v
	cd ${CURRENT_DIR} >/dev/null
	

clean:
	-rm -f ${NOISECAT_BIN}-* ${NOISESOCAT_BIN}-*

.PHONY: noisecat noisesocat all deps
