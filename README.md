# DNSense — Concurrent DNS Resolver & Cache

A small educational C++17 DNS forwarding resolver. It listens for DNS requests on localhost, forwards cache misses to upstream recursive DNS servers using UDP, and returns replies. It is not a full recursive resolver (it does not query root and authoritative servers itself).

## Build and run

Requirements: Linux or macOS (POSIX sockets), C++17 compiler, Make, SQLite3 development library. Python 3 is only needed for the offline tests. `dig` is optional for manual queries.

On Ubuntu/WSL: `sudo apt install build-essential libsqlite3-dev dnsutils python3`.
On macOS: install Xcode Command Line Tools (`xcode-select --install` if needed); the system SDK normally provides SQLite3 and macOS includes `dig`. Windows users should use WSL.

From the project directory:

```sh
make
./dnsense
```

The default listen address is 127.0.0.1:5353 (no administrator permission needed). The default upstreams are Cloudflare 1.1.1.1 and Google 8.8.8.8. In another terminal:

```sh
dig @127.0.0.1 -p 5353 example.com A +noedns +notcp +nocookie +noadflag
# Repeat the same query to observe a cache hit.
dig @127.0.0.1 -p 5353 example.com A +noedns +notcp +nocookie +noadflag
./dnsense --stats
```

Use Ctrl+C to stop. The SQLite log `queries.db` is created in the working directory. Custom configuration: `./dnsense 5353 1.1.1.1 8.8.8.8` (IPv4 upstream addresses, optional `:port`). To inspect a different log: `./dnsense --stats path/to/queries.db`.

External UDP DNS traffic must be allowed by your network. To verify functionality without internet access:

```sh
make test
```

The test starts a local fake DNS server, then checks resolution, timeout fallback, compression parsing, cache hits, TTL expiration and countdown, transaction ID handling, concurrent requests, malformed queries, SQLite analytics and failure of all upstreams. It does not contact public DNS servers.

## Code map (all implementation in src/main.cpp)

| Class | Responsibility | Core concept |
|---|---|---|
| PacketParser | Read DNS headers, questions, resource record TTLs and compressed names | Networking, binary encoding |
| Cache | Store positive DNS replies in an unordered_map; expire entries and reduce returned TTLs | Hash tables, TTL, shared_mutex |
| ThreadPool | Four worker threads wait for queued queries | Threads, mutex, condition_variable |
| UpstreamPool | Send DNS requests via UDP and try the next upstream on failure | POSIX sockets, poll, timeout, failover |
| QueryLog | Save query metadata and aggregate statistics | SQLite, SQL, prepared statements |
| Resolver | Coordinate parsing, cache lookup, forwarding, and logging | OOP, separation of responsibilities |
| main | Bind a UDP socket, receive requests and dispatch to workers | Client/server networking |

## End-to-end flow

1. A DNS client sends a UDP query to the local listener.
2. The main thread places the request in the thread pool queue.
3. A worker wakes up and parses the domain, record type and class.
4. The resolver evicts expired entries and checks its cache. A hit returns a copy of the cached response with the client's transaction ID and remaining TTLs.
5. On a miss, UpstreamPool sends a query to an upstream recursive DNS server. Each attempt has a one-second response timeout; the overall upstream response-wait budget is approximately 2.2 seconds. If an upstream times out or returns SERVFAIL/REFUSED, it tries the next one.
6. Valid complete positive responses with nonzero TTL are cached. The shortest record TTL determines cache expiration. Negative or truncated responses are not cached.
7. QueryLog records the domain, cache hit/miss, latency and DNS response code. The worker returns the response via UDP to the original client.

## Deliberate limitations

- Localhost only; ordinary single-question IPv4-transport UDP DNS requests. No EDNS, DNSSEC validation, TCP fallback, or full recursive resolution. Use the manual `dig` flags above. A truncated upstream response may be returned with the TC flag set.
- Cache is in memory, uses exact question bytes and recursion flag as its key, and expires entries when handling new queries; no background eviction, size cap, negative caching or duplicate-request coalescing.
- Four workers and an unbounded work queue are intentionally simple; not a public-facing production service. Timeout budget covers upstream waiting, not queue time or SQLite logging.
- SQLite logs queried domains locally. Do not expose this database or use it for private traffic without appropriate controls.
- Tests were run on Linux against local mock upstreams; macOS and public upstream connectivity were not independently tested.

This project is a learning implementation, not an enterprise DNS service. Only describe features you have actually run and understood in an interview.
