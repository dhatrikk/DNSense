````markdown
# DNSense - Concurrent DNS Resolver & Cache

## Contents

1. Introduction
2. Features
3. Tech Stack
4. How It Works
5. Running the Project
6. Configuration
7. Error Handling
8. Testing
9. Project Structure


## 1. Introduction

**DNSense** is a concurrent DNS resolver and caching server implemented in **C++17/20** for Linux systems.

The server accepts DNS queries over **UDP**, parses DNS wire-format messages, checks a thread-safe in-memory cache, and forwards cache misses to configured upstream DNS resolvers. Responses are cached according to their **TTL**, reducing repeated upstream requests and improving resolution performance.

The resolver supports multiple upstream DNS servers with configurable timeout and fallback handling. Concurrent DNS queries are processed using a **thread pool**, while shared cache access is protected using C++ synchronization primitives.

DNSense also records query information in **SQLite**, allowing analysis of queried domains, cache hit rates, resolution latency, and upstream usage.

The implementation focuses on five core areas:

- **Computer Networks:** UDP sockets, DNS protocol, packet parsing, upstream communication
- **Operating Systems:** threads, thread pools, synchronization, concurrent data access
- **OOP:** modular `Resolver`, `PacketParser`, `Cache`, and `UpstreamPool` components
- **DBMS:** SQLite schema, indexing, query logging, and analytics
- **System Design:** TTL caching, upstream fallback, timeout budgets, concurrency, and resource management


## 2. Features

- UDP-based DNS server
- Custom DNS wire-format packet parsing and construction
- Support for **A, AAAA, and CNAME** records
- Forwarding of unsupported record types to upstream DNS servers
- Rejection of compressed DNS names with `FORMERR`
- Case-insensitive domain normalization
- Thread-pool based concurrent query processing
- Thread-safe TTL-aware in-memory cache
- Nearest-to-expiry cache eviction
- Multiple configurable upstream DNS resolvers
- Per-attempt and overall resolution timeouts
- Automatic upstream fallback
- SQLite-based query logging
- Indexed query analytics
- YAML configuration
- Structured application logging using `spdlog`


## 3. Tech Stack

| Component | Technology |
|---|---|
| Language | C++17/20 |
| Operating System | Linux |
| Networking | POSIX UDP sockets |
| DNS Protocol | Custom DNS wire-format implementation |
| Concurrency | `std::thread`, `std::mutex`, `std::shared_mutex`, `std::condition_variable`, `std::atomic` |
| Cache | `std::unordered_map` |
| Database | SQLite |
| Database API | SQLite C API |
| Configuration | YAML + `yaml-cpp` |
| Logging | `spdlog` |
| Testing | GoogleTest |
| DNS Testing | `dig`, `nslookup` |
| Benchmarking | `dnsperf` / custom query generator |
| Build System | CMake |


## 4. How It Works

### 4.1 Query Flow

```text
Client
   |
   | UDP DNS query
   v
UDP Receiver
   |
   v
Thread Pool
   |
   v
DNS Resolver
   |
   +----> Cache HIT ----> TTL check ----> Response
   |
   +----> Cache MISS
              |
              v
        Upstream Resolver 1
              |
          timeout/failure
              |
              v
        Upstream Resolver 2
              |
              v
        DNS Response
              |
              v
        Update Cache
              |
              v
        Return Response
              |
              v
        SQLite Query Log
````

### 4.2 Cache Flow

DNSense maintains an in-memory cache using:

```text
(domain, record_type, dns_class)
```

as the cache key.

Domain names are normalized to lowercase before lookup.

Each cached response stores an expiration time based on the authoritative DNS TTL.

```text
Current Time < Expiration Time
        |
        +---- valid cache entry

Current Time >= Expiration Time
        |
        +---- cache miss
```

When the cache reaches its configured capacity, the entry with the **nearest expiration time** is removed.

### 4.3 Upstream Resolution

DNSense supports multiple configurable upstream resolvers.

Example:

```yaml
upstream:
  - host: 1.1.1.1
    port: 53

  - host: 8.8.8.8
    port: 53
```

If the first upstream fails or times out, DNSense tries the next upstream within the configured overall resolution deadline.

If all configured upstreams fail, the resolver returns `SERVFAIL`.

### 4.4 Concurrent Processing

Incoming queries are placed into a blocking task queue and processed by a fixed number of worker threads.

```text
UDP Receiver
     |
     v
Task Queue
  /  |  \
 v   v   v
W1  W2  W3
```

The cache uses `std::shared_mutex` so multiple threads can safely read cached entries while writes and evictions use exclusive access.

### 4.5 Database Logging

After a query is processed, DNSense records information in SQLite.

The stored information includes:

* Domain
* Record type
* DNS class
* Cache hit/miss
* Resolution time
* Upstream resolver used
* Timestamp

This data can be used to calculate cache hit rates, frequently queried domains, and upstream performance.

## 5. Running the Project

### Build

```bash
cmake -S . -B build
cmake --build build
```

### Run

```bash
./build/dnsense
```

By default, the resolver listens for DNS queries on the configured UDP port.

### Test with `dig`

```bash
dig @127.0.0.1 -p 5353 example.com
```

### Test with `nslookup`

```bash
nslookup example.com 127.0.0.1
```

## 6. Configuration

DNSense uses a YAML configuration file.

Example:

```yaml
server:
  host: 0.0.0.0
  port: 5353

workers:
  count: 4

upstream:
  - host: 1.1.1.1
    port: 53

  - host: 8.8.8.8
    port: 53

timeouts:
  upstream_per_attempt_ms: 1000
  total_resolution_ms: 2500

cache:
  max_entries: 10000
```

The configuration is validated during startup.

Invalid values such as invalid ports, non-positive worker counts, or invalid timeout values cause the program to terminate with an error.

## 7. Error Handling

DNSense handles the following cases:

### Malformed DNS packet

Returns:

```text
FORMERR
```

### Compressed DNS name

Compressed names are outside the project's supported DNS parsing scope and result in:

```text
FORMERR
```

### Upstream timeout

The resolver tries the next configured upstream within the overall resolution deadline.

### All upstreams unavailable

Returns:

```text
SERVFAIL
```

### Expired cache entry

The entry is treated as a cache miss and the resolver queries an upstream server.

### SQLite failure

DNS resolution continues using the in-memory cache and upstream DNS servers. The database error is recorded through application logging.

## 8. Database

DNSense uses SQLite for query logging.

### Table

```sql
CREATE TABLE query_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    record_type INTEGER NOT NULL,
    dns_class INTEGER NOT NULL,
    cache_hit INTEGER NOT NULL,
    resolution_time_ms INTEGER NOT NULL,
    upstream_used TEXT,
    timestamp INTEGER NOT NULL
);
```

### Index

```sql
CREATE INDEX idx_query_domain_time
ON query_log(domain, timestamp);
```

### Example analytics

Most queried domains:

```sql
SELECT domain, COUNT(*)
FROM query_log
GROUP BY domain
ORDER BY COUNT(*) DESC
LIMIT 10;
```

Cache hit rate:

```sql
SELECT AVG(cache_hit) * 100
FROM query_log;
```

Average upstream resolution time:

```sql
SELECT upstream_used,
       AVG(resolution_time_ms)
FROM query_log
GROUP BY upstream_used;
```

## 9. Testing

### Unit Testing

GoogleTest is used for:

* DNS header parsing
* DNS question parsing
* Cache lookup
* TTL expiration
* Cache eviction
* Domain normalization
* Configuration validation

### Integration Testing

The resolver is tested using:

```bash
dig
nslookup
```

Example workflow:

```text
First query
    |
    +--> Cache MISS --> Upstream

Second query
    |
    +--> Cache HIT

After TTL expiration
    |
    +--> Cache MISS --> Upstream
```

### Failure Testing

The following cases are tested:

* Primary upstream timeout
* Secondary upstream success
* All upstreams unavailable
* Malformed DNS packet
* Compressed-name query
* Expired cache
* Full cache
* Unsupported record type
* SQLite unavailable
* Concurrent DNS queries

## 10. Project Structure

```text
dns-resolver/
├── CMakeLists.txt
├── README.md
│
├── config/
│   └── config.yaml
│
├── include/
│   ├── dns/
│   │   ├── DnsHeader.hpp
│   │   ├── DnsQuestion.hpp
│   │   ├── DnsRecord.hpp
│   │   ├── DnsPacket.hpp
│   │   └── PacketParser.hpp
│   │
│   ├── resolver/
│   │   ├── Resolver.hpp
│   │   └── UpstreamPool.hpp
│   │
│   ├── cache/
│   │   ├── Cache.hpp
│   │   ├── CacheEntry.hpp
│   │   └── CachePolicy.hpp
│   │
│   ├── database/
│   │   ├── Database.hpp
│   │   └── QueryLogger.hpp
│   │
│   ├── concurrency/
│   │   ├── ThreadPool.hpp
│   │   └── BlockingQueue.hpp
│   │
│   └── config/
│       └── Config.hpp
│
├── src/
│   ├── dns/
│   ├── resolver/
│   ├── cache/
│   ├── database/
│   ├── concurrency/
│   ├── config/
│   └── main.cpp
│
├── tests/
│   ├── test_parser.cpp
│   ├── test_cache.cpp
│   ├── test_resolver.cpp
│   └── test_database.cpp
│
└── data/
    └── dns.db
```

## 11. Key Design Principles

### Object-Oriented Design

```text
Resolver
 ├── PacketParser
 ├── Cache
 └── UpstreamPool
```

Each component has a focused responsibility.

### Operating Systems

The project demonstrates:

* Threads
* Thread pools
* Mutexes
* Reader-writer synchronization
* Condition variables
* Producer-consumer architecture

### Computer Networks

The project demonstrates:

* UDP communication
* DNS packet structure
* DNS query/response handling
* DNS record types
* Timeouts
* Upstream communication

### DBMS

The project demonstrates:

* Relational schema
* Primary keys
* Indexing
* SQL aggregation
* Persistent query logging

### System Design

The project demonstrates:

* TTL-based caching
* Multi-upstream fallback
* Timeout budgets
* Concurrent processing
* Resource limits
* Failure handling

## 12. Project Structure Summary

DNSense combines low-level network programming with concurrent C++ design, caching, database-backed analytics, and failure handling to provide a compact but complete systems-oriented DNS resolver.

