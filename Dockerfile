FROM ubuntu:22.04

# Install build tools (build-essential already pulls in make, gcc, libc6-dev)
RUN apt-get update \
 && apt-get install -y build-essential libaio-dev pkg-config check \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY . .

# Build everything via your Makefile (which uses -D_GNU_SOURCE and links -lanl)
RUN make clean all

# Expose your SOCKS port if you like
EXPOSE 1080

# Default to running your server
CMD ["./bin/server"]
