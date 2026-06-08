# Logchewie

## Overview

**Logchewie** is a high-performance application designed to handle large volumes of syslog messages received over UDP. The application filters incoming messages based on configured text patterns and priority/facility combinations, and sends the relevant messages to specified Redis streams. The main goal of **Logchewie** is to ensure that only the most pertinent and relevant log information is processed and transmitted for further analysis.

## Features

#### RX ring
Logchewie is able to receive large volumes of traffic through [Packet MMAP](https://docs.kernel.org/networking/packet_mmap.html) interface using mmaped RX ring of packets. A dedicated thread opens a socket, sets up RX ring memory and handles incoming traffic in epoll() loop. See [src/config.h](src/config.h) for RX ring tunables.

#### Filter
For each packet received, filter code decides whether a message is accepted or rejected. Filter code runs in context of RX ring thread and no memcpy is done yet. Filter rules match certain characteristics of syslog messages and are defined in a form of a table in [src/filter.c](src/filter.c). Accepted message is pushed to the queue of one of redis threads. Rejected message is dropped and RX ring continues with next packet.

#### Redis threads
Redis threads handle accepted messages incoming from RX ring. Typically the communication with redis cluster is much slower than RX ring processing therefore the traffic is split into multiple redis threads where the messages can be consumed at slower pace. The number of redis threads is configurable with -t --redis_threads option or REDIS_THREADS env. Each redis thread owns a message queue to which RX ring pushes accepted messages and redis thread consumes from. The size of the queue is configured in [src/config.h](src/config.h). The size of the queues determines how much traffic can be stored in case of redis cluster connectivity errors. For example if the traffic is 32k accepted msg/s and there are 8 redis threads and the queue size is 256k elements then logchewie can store up to 64 seconds of traffic.

## Installation

### Prerequisites

- **C compiler**
- **hiredis**: Redis client library
- **hiredis-cluster**: Redis cluster client library
- **yyjson**: C JSON library
- **CUnit**: Unit testing framework

### Build Instructions

1. **Clone the Repository**

   ```bash
   git clone ssh://git@bitbucket.altibox.net:7999/bbp/network_syslog_collector.git
   ```

2. **Install prerequisites**

    For compilation directly on host you need to compile and install all prerequisites first. See how it is done in [docker/Dockerfile.ubi9](docker/Dockerfile.ubi9) for example.

3. **Run the Makefile**

   ```bash
   make
   ```

### Docker builds

Alternatively you can build and run one of available logchewie docker images:

  * [docker/Dockerfile.ubi7](docker/Dockerfile.ubi7)
  * [docker/Dockerfile.ubi8](docker/Dockerfile.ubi8)
  * [docker/Dockerfile.ubi9](docker/Dockerfile.ubi9)

More details on building and running them is stored in first lines of each Dockerfile.

ubi7 image build:
```bash
docker build -f docker/Dockerfile.ubi7 --build-arg CACHE_BUST=$(date +%s) -t logchewie-ubi7:latest .
```

## Configuration

logchewie is configured in two ways: at compile time by defines stored in [src/config.h](src/config.h) and by runtime options.

```bash
Usage: ./build/logchewie [options]
Options:
  -h, --help
  -i, --interface                      Listen on this interface only
  -s, --redis_servers <servers>        Redis servers
  -t, --redis_threads <nr>             Number of redis threads
  -v, --verbose                        Verbose output
  -a, --stats                          Print stats every second

Environment variables:
  INTERFACE REDIS_SERVERS REDIS_THREADS VERBOSE STATS
```

## Usage

Basic usage is as follows:

```bash
./build/logchewie -s 127.0.0.1:7000 -i eth1 -t 128 -a
```

Please refer to [configuration](#configuration) section to see available configuration options.

## Logchewie architecture

![Logchewie](diagrams/logchewie_arch.svg)

Logchewie operation is based mainly on three components:
- rx-ring - Uses BPF filter on the raw socket to filter incoming UDP packets with dst port 514. Raw socket and [Packet MMAP](https://docs.kernel.org/networking/packet_mmap.html) interface allow to receive high volume syslog messages.
- filter - The filter decides whether incomming messages are accepted or rejected. Filter rules match certain characteristics of syslog messages and are defined in a form of a table in [src/filter.c](src/filter.c).
- redis send - Runs multipple redis threads. Threads handle accepted messages incoming from RX ring. Each redis thread owns a message queue. Messages are published to redis cluster.

Additionally there are following helper/utility modules:

- utils - Generic helper module, e.g. time measurement.
- config - Provides default configuration, allows for setting configuration vie ENVs or command line parameters.
- stats - Prints periodicaly operation statistics.


## Lab tests

#### Setup
We measured logchewie performance in an isolated environment where two PCs were connected via 10Gbit/s fibre link. The PC where logchewie ran was Intel i9 9900k + 64GB RAM + 10G mellanox eth. Syslog traffic was generated from the other PC with [syslog-traffic-generator](utils/syslog-traffic-generator). The redis cluster was configured as 16 master node with no replicas.

#### Test 1 - worst case scenario
100% of traffic is accepted in filter (rule 6 is of "catch all" type) and sent to redis cluster with XADD command. The max we could get in this configuration was ~1M XADD commands / second (with good key to shard distribution, see GET_STREAM macro in [src/redis.c](src/redis.c)). Logchewie was running with 32 redis threads.
```
[rx-ring] 1020.1 k pkts/s, 2538.9 Mbit/s, 0 drops, 0 freeze, 0 overflow
[filter] 100.0 % (1020.6 k) accepted / 0.0 % (0.0 k) rejected
[redis-0] 31.7 k msg/s, 78.9 Mbit/s, qlen 295/250000 0.1%, 12.6 us/msg
...
[redis-31] 32.3 k msg/s, 80.2 Mbit/s, qlen 191/250000 0.1%, 12.8 us/msg
```

#### Test 2 - max numbers
As the redis cluster throughput was the limiting factor we commented out functions sending commands to redis and tested what logchewie can handle. At these rates the environment became unstable - a browser running in the background could cause RX ring drops, etc.
```
[rx-ring] 3027.9 k pkts/s, 4054.8 Mbit/s, 0 drops, 0 freeze, 0 overflow
[filter] 100.0 % (3032.8 k) accepted / 0.0 % (0.0 k) rejected
[redis-0] 63.2 k msg/s, 84.5 Mbit/s, qlen 0/262144 0.0%, 2.1 us/msg
...
[redis-47] 63.2 k msg/s, 84.4 Mbit/s, qlen 0/262144 0.0%, 1.9 us/msg
```

#### Conclusion
In real life scenario probably ~80% of traffic will be filtered out. Logchewie should be able to handle up to 1M pkts/s assuming it has enough resources and redis cluster can handle this volume. Anything beyond that requires more OS tuning - increase eth card RX ring buffers, check logchewie RX ring thread priority vs other processes in the system, adjust RX ring sizes, adjust redis threads queue sizes, etc.
