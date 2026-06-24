# Build Stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the proxy and benchmark binaries
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/atlas-proxy ./atlas/cmd/atlas-proxy/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/atlas-bench ./atlas/cmd/atlas-bench/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/ablation-bench ./atlas/cmd/ablation-bench/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/adaptive-bench ./atlas/cmd/adaptive-bench/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/live-validation ./atlas/cmd/live-validation/main.go

# Runtime Stage
FROM alpine:latest

WORKDIR /app

# Install CA certificates for outbound TLS connections
RUN apk --no-cache add ca-certificates

# Copy compiled binaries from builder
COPY --from=builder /bin/atlas-proxy /bin/atlas-proxy
COPY --from=builder /bin/atlas-bench /bin/atlas-bench
COPY --from=builder /bin/ablation-bench /bin/ablation-bench
COPY --from=builder /bin/adaptive-bench /bin/adaptive-bench
COPY --from=builder /bin/live-validation /bin/live-validation

# Expose the default proxy port
EXPOSE 1080

# By default, run the proxy and generate the MITM certificates automatically
CMD ["/bin/atlas-proxy", "--generate-cert", "--listen", ":1080"]
