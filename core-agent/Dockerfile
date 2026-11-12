FROM ubuntu:22.04

# Install ONLY the necessary runtime libraries (no compilers!)
# Note: Ubuntu 22.04 uses libbpf0 instead of libbpf1
RUN apt-get update && apt-get install -y \
    libbpf0 \
    libelf1 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy our compiled binary
COPY loader /app/loader

# Run the agent
CMD ["./loader"]
