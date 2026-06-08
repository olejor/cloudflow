# Use an official base image with a C compiler, like GCC
FROM gcc:latest

# Install any dependencies your application might need
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libpthread-stubs0-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the source code into the container
WORKDIR /usr/src/udp2http
COPY src/ ./src/
COPY Makefile ./

# Compile the application
RUN make

# Run the application
CMD ["./udp2http"]