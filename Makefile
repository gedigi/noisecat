NOISECAT_BIN := noisecat
GOARCH := amd64

CURRENT_DIR := $(shell pwd)
NOISECAT_SRC := $(CURRENT_DIR)/cmd/noisecat
BIN_DIR := $(CURRENT_DIR)/bin

LDFLAGS := -s -w

PLATFORMS := linux darwin windows freebsd

.PHONY: all test vet lint clean $(PLATFORMS)

all: $(PLATFORMS)

test:
	go test -race -coverprofile=coverage.out ./...

vet:
	go vet ./...

lint:
	golangci-lint run

linux darwin freebsd:
	mkdir -p $(BIN_DIR)
	GOOS=$@ GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" \
		-o $(BIN_DIR)/$(NOISECAT_BIN)-$@-$(GOARCH) $(NOISECAT_SRC)

windows:
	mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" \
		-o $(BIN_DIR)/$(NOISECAT_BIN)-windows-$(GOARCH).exe $(NOISECAT_SRC)

clean:
	rm -rf $(BIN_DIR) coverage.out
