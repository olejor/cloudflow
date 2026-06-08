# UDP to HTTP POST Server

## Overview
This application is a UDP server that listens for incoming UDP packets on a specified port. Upon receiving data, it forwards the content to a predefined HTTP server URL via POST requests.

## Features
- Listens for UDP packets on a configurable port.
- Forwards received data to a specified HTTP server using POST request.
- Configurable timeout for HTTP requests.
- Supports different log levels and optional stdout logging.
- Accepts command-line arguments for easy configuration.

## Requirements
- GCC (GNU Compiler Collection)
- `libcurl` development libraries

## Building the Application

### Compilation
1. **Clone the repository**
git clone [repository-url]
2. **Navigate to the project directory**:
cd path/to/udp2http
3. **Compile the application**:
make

## Usage
Run the application with the following command-line arguments:
- `-p`: Port to listen for UDP packets (1024-65535).
- `-u`: URL of the HTTP server for POST requests.
- `-t`: Timeout for HTTP POST requests in milliseconds (0-10000).
- `-l`: Log level (integer, e.g., 6 for LOG_INFO).
- `-s`: Enable stdout logging (boolean).
- `-n`: Custom log name (string).

Example:
./udp2http -u "http://example.com/post" -p 8080 -t 5000 -l 6 -s true -n ""
./udp2http -u "http://example.com/post" -p 8081 -t 5000 -l 6 -s true -n "udp2transit"

## Configuration

- Update the `MAXLINE` and `QUEUE_SIZE` macros in the source code for different buffer sizes and queue capacities.