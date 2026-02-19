# Контекст сборки HA = папка аддона
# Builder — явно golang (HA передаёт BUILD_FROM=amd64-base, в котором нет Go).
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY agent-go/go.mod ./
RUN go mod tidy 2>/dev/null || true
COPY agent-go/ ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /tinta-agent .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /tinta-agent /usr/local/bin/tinta-agent
COPY run.sh /run.sh
RUN chmod +x /run.sh
ENTRYPOINT ["/run.sh"]