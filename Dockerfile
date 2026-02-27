FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /docker-hardened-proxy ./cmd/docker-hardened-proxy

FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY --from=builder /docker-hardened-proxy /usr/local/bin/docker-hardened-proxy

ENTRYPOINT ["docker-hardened-proxy"]
CMD ["-config", "/etc/docker-hardened-proxy/config.yaml"]
