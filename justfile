default:
    @just --list

build:
    go build -o docker-hardened-proxy ./cmd/docker-hardened-proxy

run *ARGS:
    go run ./cmd/docker-hardened-proxy {{ARGS}}

test:
    go test ./...

test-v:
    go test -v ./...

lint:
    go vet ./...

clean:
    rm -f docker-hardened-proxy
