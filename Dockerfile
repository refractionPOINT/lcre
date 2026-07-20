# Build stage
FROM golang:1.25-bookworm AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with version from git
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/refractionPOINT/lcre/internal/cli.Version=${VERSION} -X github.com/refractionPOINT/lcre/internal/cli.BuildTime=$(date -u '+%Y-%m-%d_%H:%M:%S')" \
    -o /lcre ./cmd/lcre

# Runtime stage with Ghidra
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    wget \
    p7zip-full \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
ARG GHIDRA_VERSION=11.0.3
ARG GHIDRA_DATE=20240410

RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip \
    -O /tmp/ghidra.zip && \
    7z x -y -o/opt /tmp/ghidra.zip > /dev/null && \
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
