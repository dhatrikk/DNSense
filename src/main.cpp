#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <sqlite3.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cstdint>
#include <functional>
#include <iostream>
#include <mutex>
#include <queue>
#include <random>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <csignal>

using Bytes = std::vector<uint8_t>;
using Clock = std::chrono::steady_clock;

// 1. PACKET PARSER: DNS messages are binary packets, not ordinary strings.
class PacketParser {
public:
    // Read two bytes as one number, in network (big-endian) order.
    static uint16_t u16(const Bytes& packet, size_t offset) {
        if (offset + 2 > packet.size()) {
            throw std::runtime_error("truncated DNS packet");
        }
        return (uint16_t(packet[offset]) << 8) | packet[offset + 1];
    }

    static uint32_t u32(const Bytes& packet, size_t offset) {
        return (uint32_t(u16(packet, offset)) << 16) | u16(packet, offset + 2);
    }

    // Write a number back into the packet (for example, a transaction ID).
    static void put16(Bytes& packet, size_t offset, uint16_t value) {
        packet.at(offset) = value >> 8;
        packet.at(offset + 1) = value & 255;
    }

    static void put32(Bytes& packet, size_t offset, uint32_t value) {
        put16(packet, offset, value >> 16);
        put16(packet, offset + 2, value & 65535);
    }

    // Read a domain name. DNS may use a pointer to an earlier name
    // instead of repeating the same bytes (DNS name compression).
    static std::string name(const Bytes& packet, size_t& position) {
        size_t cursor = position;
        bool followedPointer = false;
        std::string result;

        for (size_t steps = 0; steps <= packet.size(); ++steps) {
            if (cursor >= packet.size()) {
                throw std::runtime_error("bad DNS name");
            }
            unsigned length = packet[cursor++];

            if ((length & 0xc0) == 0xc0) {
                if (cursor >= packet.size()) {
                    throw std::runtime_error("bad pointer");
                }
                size_t target = ((length & 63) << 8) | packet[cursor++];
                if (target >= cursor - 2) {
                    throw std::runtime_error("invalid compression pointer");
                }
                // Remember where the original name ends, not the pointer target.
                if (!followedPointer) {
                    position = cursor;
                }
                followedPointer = true;
                cursor = target;
                continue;
            }

            // A zero-length label marks the end of a domain name.
            if (length == 0) {
                if (!followedPointer) {
                    position = cursor;
                }
                return result;
            }

            if (length > 63 || cursor + length > packet.size() ||
                result.size() + length + 1 > 254) {
                throw std::runtime_error("bad label");
            }
            // Keep the label lengths to make an unambiguous comparison key.
            result.push_back(char(length));
            for (unsigned i = 0; i < length; ++i) {
                unsigned char letter = packet[cursor++];
                result.push_back(char(std::tolower(letter)));
            }
        }
        throw std::runtime_error("compression loop");
    }

    struct Question {
        std::string key;
        std::string display;
        uint16_t type;
        uint16_t cls;
        size_t end;
    };

    static Question question(const Bytes& packet) {
        // The DNS header is 12 bytes; this project supports one question.
        if (packet.size() < 12 || u16(packet, 4) != 1) {
            throw std::runtime_error("expected one question");
        }
        size_t position = 12;
        auto domain = name(packet, position);
        auto type = u16(packet, position);
        auto recordClass = u16(packet, position + 2);
        position += 4;

        // Convert length-prefixed labels to a readable domain for logging.
        std::string display;
        for (size_t i = 0; i < domain.size();) {
            unsigned length = uint8_t(domain[i++]);
            if (!display.empty()) {
                display += '.';
            }
            display += domain.substr(i, length);
            i += length;
        }
        std::string key = domain + char(0) + char(type >> 8) + char(type)
                          + char(recordClass >> 8) + char(recordClass);
        return {key, display, type, recordClass, position};
    }

    struct TTL {
        size_t offset;
        uint32_t seconds;
    };

    // Find every record's TTL and its byte position for cache countdown.
    static std::vector<TTL> ttls(const Bytes& packet) {
        size_t position = question(packet).end;
        std::vector<TTL> result;

        // DNS records are grouped into answer, authority and additional sections.
        for (int section = 0; section < 3; ++section) {
            unsigned count = u16(packet, 6 + 2 * section);
            for (unsigned i = 0; i < count; ++i) {
                name(packet, position);
                auto type = u16(packet, position);
                auto ttl = u32(packet, position + 4);
                auto dataLength = u16(packet, position + 8);
                if (type != 41) { // OPT records do not have a normal TTL.
                    result.push_back({position + 4, ttl});
                }
                position += 10 + dataLength;
                if (position > packet.size()) {
                    throw std::runtime_error("truncated record");
                }
            }
        }
        if (position != packet.size()) {
            throw std::runtime_error("unexpected trailing data");
        }
        return result;
    }

    // Create a DNS error response with the client's original transaction ID.
    static Bytes error(const Bytes& query, uint16_t rcode) {
        Bytes response(12, 0);
        if (query.size() >= 2) {
            put16(response, 0, u16(query, 0));
        }
        uint16_t recursionFlag = query.size() >= 4 ? u16(query, 2) & 0x0100 : 0;
        put16(response, 2, 0x8080 | recursionFlag | rcode);
        try {
            auto q = question(query);
            response.insert(response.end(), query.begin() + 12, query.begin() + q.end);
            put16(response, 4, 1);
        } catch (...) {
            // A malformed question may not be safe to copy.
        }
        return response;
    }
};

// 2. CACHE: remember successful DNS responses until their TTL expires.
class Cache {
    struct Entry {
        Bytes packet;
        std::vector<PacketParser::TTL> ttls;
        Clock::time_point saved;
        Clock::time_point expires;
    };
    std::unordered_map<std::string, Entry> entries;
    std::shared_mutex mutex;

public:
    bool get(const std::string& key, uint16_t id, Bytes& response) {
        // Multiple worker threads may read the cache simultaneously.
        std::shared_lock<std::shared_mutex> lock(mutex);
        auto it = entries.find(key);
        auto now = Clock::now();
        if (it == entries.end() || now >= it->second.expires) {
            return false;
        }

        const auto& entry = it->second;
        response = entry.packet; // Copy so we do not modify the shared entry.
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - entry.saved).count();
        for (auto ttl : entry.ttls) {
            uint32_t remaining = age >= ttl.seconds ? 0 : ttl.seconds - uint32_t(age);
            PacketParser::put32(response, ttl.offset, remaining);
        }
        PacketParser::put16(response, 0, id);
        return true;
    }

    void evictExpired() {
        // Removing entries requires exclusive access to the cache.
        std::unique_lock<std::shared_mutex> lock(mutex);
        auto now = Clock::now();
        for (auto it = entries.begin(); it != entries.end();) {
            if (now >= it->second.expires) {
                it = entries.erase(it);
            } else {
                ++it;
            }
        }
    }

    void put(const std::string& key, const Bytes& response) {
        auto flags = PacketParser::u16(response, 2);
        bool truncated = (flags & 0x0200) != 0;
        bool hasError = (flags & 0x000f) != 0;
        bool hasAnswers = PacketParser::u16(response, 6) != 0;
        if (truncated || hasError || !hasAnswers) {
            return;
        }
        auto ttls = PacketParser::ttls(response);
        if (ttls.empty()) {
            return;
        }
        // A packet expires when its shortest-lived record expires.
        uint32_t minimumTTL = ttls.front().seconds;
        for (auto ttl : ttls) {
            minimumTTL = std::min(minimumTTL, ttl.seconds);
        }
        if (minimumTTL == 0) {
            return;
        }
        auto now = Clock::now();
        std::unique_lock<std::shared_mutex> lock(mutex);
        entries.insert_or_assign(key, Entry{response, ttls, now,
                                            now + std::chrono::seconds(minimumTTL)});
    }
};

// 3. THREAD POOL: reuse a fixed number of threads to process DNS queries.
class ThreadPool {
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> jobs;
    std::mutex mutex;
    std::condition_variable cv;
    bool stopping = false;

    void workerLoop() {
        while (true) {
            std::function<void()> job;
            {
                std::unique_lock<std::mutex> lock(mutex);
                // Sleep when there is no work; wake up when a job is added.
                cv.wait(lock, [this] { return stopping || !jobs.empty(); });
                if (stopping && jobs.empty()) {
                    return;
                }
                job = std::move(jobs.front());
                jobs.pop();
            } // Release the queue lock before doing network work.
            job();
        }
    }

public:
    explicit ThreadPool(size_t count) {
        for (size_t i = 0; i < count; ++i) {
            workers.emplace_back([this] { workerLoop(); });
        }
    }

    void submit(std::function<void()> job) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            jobs.push(std::move(job));
        }
        cv.notify_one();
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            stopping = true;
        }
        cv.notify_all();
        for (auto& worker : workers) {
            worker.join();
        }
    }
};

// A small RAII wrapper closes a socket automatically when it goes out of scope.
struct Socket {
    int fd;
    explicit Socket(int descriptor) : fd(descriptor) {}
    ~Socket() {
        if (fd >= 0) {
            close(fd);
        }
    }
    Socket(const Socket&) = delete;
};

// 4. UPSTREAM POOL: forward cache misses and try another server on failure.
class UpstreamPool {
    std::vector<sockaddr_in> servers;

    // Ensure that an upstream reply belongs to the question we sent.
    static bool matchesQuery(const Bytes& response, uint16_t id, const std::string& key) {
        auto flags = PacketParser::u16(response, 2);
        bool isResponse = (flags & 0x8000) != 0;
        bool standardOpcode = (flags & 0x7800) == 0;
        return PacketParser::u16(response, 0) == id && isResponse && standardOpcode &&
               PacketParser::question(response).key == key;
    }

public:
    explicit UpstreamPool(const std::vector<std::string>& addresses) {
        for (const auto& address : addresses) {
            sockaddr_in server{};
            server.sin_family = AF_INET;
            auto colon = address.find(':');
            int port = colon == std::string::npos ? 53 : std::stoi(address.substr(colon + 1));
            if (port < 1 || port > 65535 ||
                inet_pton(AF_INET, address.substr(0, colon).c_str(), &server.sin_addr) != 1) {
                throw std::runtime_error("invalid upstream");
            }
            server.sin_port = htons(port);
            servers.push_back(server);
        }
    }

    Bytes resolve(Bytes query, const std::string& key) const {
        uint16_t originalId = PacketParser::u16(query, 0);
        thread_local std::random_device random;
        // At most 1 second per server, with a 2.2-second overall waiting budget.
        auto deadline = Clock::now() + std::chrono::milliseconds(2200);

        for (const auto& server : servers) {
            Socket sock(socket(AF_INET, SOCK_DGRAM, 0));
            if (sock.fd < 0) {
                continue;
            }
            // UDP connect selects a peer; it does not establish a TCP handshake.
            if (connect(sock.fd, reinterpret_cast<const sockaddr*>(&server), sizeof(server)) < 0) {
                continue;
            }
            uint16_t upstreamId = uint16_t(random());
            PacketParser::put16(query, 0, upstreamId);
            if (send(sock.fd, query.data(), query.size(), 0) != ssize_t(query.size())) {
                continue;
            }
            auto attemptDeadline = std::min(deadline, Clock::now() + std::chrono::milliseconds(1000));

            while (Clock::now() < attemptDeadline) {
                int remainingMs = int(std::chrono::duration_cast<std::chrono::milliseconds>(
                    attemptDeadline - Clock::now()).count());
                pollfd event{sock.fd, POLLIN, 0};
                if (poll(&event, 1, std::max(1, remainingMs)) <= 0) {
                    break; // Timeout: try the next upstream.
                }
                Bytes response(65535);
                auto received = recv(sock.fd, response.data(), response.size(), 0);
                if (received < 12) {
                    break;
                }
                response.resize(size_t(received));

                try {
                    if (!matchesQuery(response, upstreamId, key)) {
                        continue;
                    }
                    auto flags = PacketParser::u16(response, 2);
                    auto rcode = flags & 15;
                    if (rcode == 2 || rcode == 5) {
                        break; // SERVFAIL or REFUSED: try another server.
                    }
                    if (!(flags & 0x0200)) {
                        PacketParser::ttls(response); // Check record boundaries.
                    }
                    PacketParser::put16(response, 0, originalId);
                    return response;
                } catch (...) {
                    continue; // Ignore malformed replies within the timeout.
                }
            }
            if (Clock::now() >= deadline) {
                break;
            }
        }
        return PacketParser::error(query, 2); // Resolver restores the original ID.
    }
};

// 5. QUERY LOG: persist basic query information in SQLite.
class QueryLog {
    sqlite3* db = nullptr;
    std::mutex mutex;

public:
    explicit QueryLog(const std::string& path) {
        if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
            sqlite3_close(db);
            throw std::runtime_error("cannot open database");
        }
        const char* sql =
            "CREATE TABLE IF NOT EXISTS queries("
            "id INTEGER PRIMARY KEY, time TEXT DEFAULT CURRENT_TIMESTAMP, "
            "domain TEXT, cache_hit INTEGER, latency_ms INTEGER, rcode INTEGER);";
        if (sqlite3_exec(db, sql, nullptr, nullptr, nullptr) != SQLITE_OK) {
            sqlite3_close(db);
            throw std::runtime_error("cannot create log table");
        }
    }

    ~QueryLog() {
        sqlite3_close(db);
    }

    void add(const std::string& domain, bool hit, long ms, int rcode) {
        // Only one worker writes to this shared SQLite connection at a time.
        std::lock_guard<std::mutex> lock(mutex);
        sqlite3_stmt* statement = nullptr;
        const char* sql = "INSERT INTO queries(domain,cache_hit,latency_ms,rcode) VALUES(?,?,?,?)";
        if (sqlite3_prepare_v2(db, sql, -1, &statement, nullptr) != SQLITE_OK) {
            return;
        }
        // Bind values rather than constructing SQL from user input.
        sqlite3_bind_text(statement, 1, domain.data(), int(domain.size()), SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, hit);
        sqlite3_bind_int64(statement, 3, ms);
        sqlite3_bind_int(statement, 4, rcode);
        if (sqlite3_step(statement) != SQLITE_DONE) {
            std::cerr << "log write failed\n";
        }
        sqlite3_finalize(statement);
    }

    void stats() {
        sqlite3_stmt* statement = nullptr;
        const char* sql = "SELECT COUNT(*),COALESCE(SUM(cache_hit),0),"
                          "COALESCE(AVG(latency_ms),0),COALESCE(SUM(rcode!=0),0) FROM queries";
        if (sqlite3_prepare_v2(db, sql, -1, &statement, nullptr) != SQLITE_OK) {
            throw std::runtime_error("stats query failed");
        }
        if (sqlite3_step(statement) == SQLITE_ROW) {
            std::cout << "Queries: " << sqlite3_column_int64(statement, 0) << '\n';
            std::cout << "Cache hits: " << sqlite3_column_int64(statement, 1) << '\n';
            std::cout << "Average latency (ms): " << sqlite3_column_double(statement, 2) << '\n';
            std::cout << "Nonzero DNS response codes: " << sqlite3_column_int64(statement, 3) << '\n';
        }
        sqlite3_finalize(statement);
    }
};

// 6. RESOLVER: the main workflow for a single DNS request.
class Resolver {
    Cache cache;
    UpstreamPool upstream;
    QueryLog log;

    // This learning project supports ordinary IN queries, without EDNS/DNSSEC.
    static bool supported(const Bytes& query, const PacketParser::Question& q) {
        auto flags = PacketParser::u16(query, 2);
        return !(flags & ~0x0100) && q.cls == 1 &&
               PacketParser::u16(query, 6) == 0 && // No answer records in a query.
               PacketParser::u16(query, 8) == 0 && // No authority records.
               PacketParser::u16(query, 10) == 0 && // No additional records.
               q.end == query.size();
    }

public:
    Resolver(const std::vector<std::string>& servers, const std::string& path)
        : upstream(servers), log(path) {}

    Bytes handle(const Bytes& query) {
        auto start = Clock::now();
        Bytes response;
        std::string domain = "?";
        bool hit = false;

        try {
            auto q = PacketParser::question(query);
            domain = q.display;
            if (!supported(query, q)) {
                response = PacketParser::error(query, 4); // NOTIMP
            } else {
                uint16_t id = PacketParser::u16(query, 0);
                auto flags = PacketParser::u16(query, 2);
                // Use exact question bytes and recursion flag as cache key.
                std::string key = std::string(query.begin() + 12, query.end()) +
                                  char(bool(flags & 0x0100));
                cache.evictExpired();
                hit = cache.get(key, id, response);
                if (!hit) {
                    response = upstream.resolve(query, q.key);
                    PacketParser::put16(response, 0, id);
                    cache.put(key, response);
                }
            }
        } catch (...) {
            response = PacketParser::error(query, 1); // FORMERR
        }

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
        log.add(domain, hit, ms, PacketParser::u16(response, 2) & 15);
        return response;
    }
};

// 7. MAIN: start a UDP server, receive queries and send them to worker threads.
volatile std::sig_atomic_t running = 1;
void stop(int) {
    running = 0;
}

int main(int argc, char** argv) {
    try {
        if (argc > 1 && std::string(argv[1]) == "--stats") {
            QueryLog log(argc > 2 ? argv[2] : "queries.db");
            log.stats();
            return 0;
        }
        int port = argc > 1 ? std::stoi(argv[1]) : 5353;
        if (port < 1 || port > 65535) {
            throw std::runtime_error("invalid port");
        }
        std::vector<std::string> upstreams;
        for (int i = 2; i < argc; ++i) {
            upstreams.emplace_back(argv[i]);
        }
        if (upstreams.empty()) {
            upstreams = {"1.1.1.1", "8.8.8.8"};
        }

        Socket listener(socket(AF_INET, SOCK_DGRAM, 0));
        if (listener.fd < 0) {
            throw std::runtime_error("socket failed");
        }
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = htons(port);
        local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener.fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
            throw std::runtime_error("bind failed");
        }

        Resolver resolver(upstreams, "queries.db");
        ThreadPool workers(4); // Workers finish before resolver and socket are destroyed.
        std::signal(SIGINT, stop);
        std::signal(SIGTERM, stop);
        std::cout << "DNSense listening on 127.0.0.1:" << port << std::endl;

        while (running) {
            // Poll with a short timeout so Ctrl+C can stop the listener.
            pollfd event{listener.fd, POLLIN, 0};
            if (poll(&event, 1, 200) <= 0) {
                continue;
            }
            Bytes query(65535);
            sockaddr_in client{};
            socklen_t length = sizeof(client);
            auto received = recvfrom(listener.fd, query.data(), query.size(), 0,
                                     reinterpret_cast<sockaddr*>(&client), &length);
            if (received < 0) {
                continue;
            }
            query.resize(size_t(received));

            // Each job owns its query and client address; the resolver is shared.
            workers.submit([&, query = std::move(query), client, length] {
                auto response = resolver.handle(query);
                sendto(listener.fd, response.data(), response.size(), 0,
                       reinterpret_cast<const sockaddr*>(&client), length);
            });
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
