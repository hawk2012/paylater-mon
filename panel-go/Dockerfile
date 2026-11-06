# Dockerfile для Paylater Monitor (multi-stage build).
# Пункт 13 IMPROVEMENTS.md.
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o paylater-mon ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/paylater-mon .
COPY --from=builder /app/static ./static
COPY --from=builder /app/internal/web/templates ./templates
COPY --from=builder /app/config.yaml ./config.yaml

EXPOSE 9090
ENTRYPOINT ["./paylater-mon", "-config", "config.yaml"]
