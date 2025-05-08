# Build stage - using a specific debian version for consistency
FROM debian:bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get -y install golang git libpcap-dev ca-certificates \
    && update-ca-certificates

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN go get -d -v ./... && \
    go build -o kafka_sniffer -v cmd/sniffer/main.go

# Runtime stage - using the same debian version
FROM debian:bookworm

# Install runtime dependencies and libcap for setting capabilities
RUN apt-get update && apt-get -y install libpcap0.8 ca-certificates libcap2-bin && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy only the binary from builder stage
COPY --from=builder /app/kafka_sniffer /app/kafka_sniffer

# Set capabilities on the binary
RUN setcap cap_net_raw,cap_net_admin=eip /app/kafka_sniffer

# Set entrypoint
ENTRYPOINT ["/app/kafka_sniffer"]
