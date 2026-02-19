# Сборка: контекст = корень репо (HA клонирует весь репозиторий)
ARG BUILD_FROM=golang:1.22-alpine
FROM ${BUILD_FROM} AS builder
WORKDIR /build
COPY tinta_smart_agent/agent-go/go.mod tinta_smart_agent/agent-go/go.sum* ./
RUN go mod tidy 2>/dev/null || true
COPY tinta_smart_agent/agent-go/ ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /tinta-agent .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /tinta-agent /usr/local/bin/tinta-agent
COPY tinta_smart_agent/run.sh /run.sh
RUN chmod +x /run.sh
ENTRYPOINT ["/run.sh"]
