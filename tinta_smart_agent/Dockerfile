# Сборка: из корня репозитория
#   docker build -f agent-ha-addon/tinta_smart_agent/Dockerfile -t tinta_smart_agent .
ARG BUILD_FROM=golang:1.22-alpine
FROM ${BUILD_FROM} AS builder
WORKDIR /build
COPY agent-go/go.mod agent-go/go.sum* ./
RUN go mod tidy 2>/dev/null || true
COPY agent-go/ ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /tinta-agent .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /tinta-agent /usr/local/bin/tinta-agent
COPY tinta_smart_agent/run.sh /run.sh
RUN chmod +x /run.sh
ENTRYPOINT ["/run.sh"]
