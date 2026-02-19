# Сборка бинарника агента для linux/amd64 (HAOS, большинство mini-PC)
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod tidy 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /tinta-agent .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /tinta-agent /usr/local/bin/tinta-agent
ENTRYPOINT ["/usr/local/bin/tinta-agent"]
