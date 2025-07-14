FROM ubuntu:22.04

# Install build tools and Clang for ASan
RUN apt-get update \
 && apt-get install -y \
    build-essential \
    clang \
    libaio-dev \
    pkg-config \
    check \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY . .

# Build with AddressSanitizer (fast, powerful leak detection)
# Override SAN_FLAGS in Makefile
RUN make clean all SAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address"

# Expose your SOCKS port and extra port
EXPOSE 1080 8080

# Configure ASan and LeakSanitizer options for verbose reporting (output to stderr)
ENV ASAN_OPTIONS=detect_leaks=1:log_threads=1:verbosity=1
ENV LSAN_OPTIONS=verbosity=1:log_threads=1

# Entry point: run instrumented binary (no Valgrind needed)
ENTRYPOINT ["./bin/server", "-a", "user:pass"]
