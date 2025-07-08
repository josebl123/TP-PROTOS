FROM ubuntu:22.04

# Install build tools (build-essential already pulls in make, gcc, libc6-dev)
RUN apt-get update \
 && apt-get install -y build-essential libaio-dev pkg-config check \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY . .

# Build everything via your Makefile (which uses -D_GNU_SOURCE and links -lanl)
RUN make clean all

# Expose your SOCKS port **and** the extra port 8080
EXPOSE 1080 8080

# Default to running your server with the -a user:pass flag
CMD ["./bin/server", "-a", "user:pass"]
