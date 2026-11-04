BIN := bin/jcrelay

.PHONY: build build-linux test lint run-dev clean

build:
	go build -trimpath -o $(BIN) ./cmd/jcrelay

build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/jcrelay-linux-amd64 ./cmd/jcrelay

test:
	go test ./... -race

lint:
	go vet ./...

run-dev:
	DEV_LOGIN=1 LISTEN_ADDR=127.0.0.1:8080 DB_PATH=$${TMPDIR:-/tmp}/jcrelay-dev.db go run ./cmd/jcrelay

clean:
	rm -rf bin
