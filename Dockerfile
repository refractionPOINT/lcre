# Build stage
FROM golang:1.24-bookworm AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /lcre ./cmd/lcre

# Runtime stage with Ghidra
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
ARG GHIDRA_VERSION=11.0.3
ARG GHIDRA_DATE=20240410

RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip \
    -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra && \
    rm /tmp/ghidra.zip

ENV GHIDRA_HOME=/opt/ghidra
ENV PATH="${GHIDRA_HOME}/support:${PATH}"

# Copy binary from builder
COPY --from=builder /lcre /usr/local/bin/lcre

# Copy Ghidra scripts
COPY scripts/ghidra /opt/lcre/scripts/ghidra
ENV LCRE_SCRIPTS_PATH=/opt/lcre/scripts/ghidra

# Create work directory
WORKDIR /work

ENTRYPOINT ["lcre"]
CMD ["--help"]
