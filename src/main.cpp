#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <sqlite3.h>
#include <algorithm>
#include <atomic>
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
#include <cerrno>
#include <csignal>
using Bytes = std::vector<uint8_t>;
using Clock = std::chrono::steady_clock;

// DNS wire format: integers are stored in network (big-endian) byte order.
class PacketParser {
public:
    static uint16_t u16(const Bytes& b, size_t p) {
        if (p+2>b.size()) throw std::runtime_error("truncated DNS packet");
        return (uint16_t(b[p])<<8)|b[p+1];
    }
    static uint32_t u32(const Bytes& b,size_t p) {
        return (uint32_t(u16(b,p))<<16)|u16(b,p+2);
    }
    static void put16(Bytes& b,size_t p,uint16_t v) { b.at(p)=v>>8; b.at(p+1)=v&255; }
    static void put32(Bytes& b,size_t p,uint32_t v) { put16(b,p,v>>16); put16(b,p+2,v&65535); }
    // Follow compressed names (0xc0 pointers), but advance the original cursor only once.
    static std::string name(const Bytes& b,size_t& pos) {
        size_t p=pos; bool jumped=false; std::string out;
        for(size_t steps=0; steps<=b.size(); ++steps) {
            if(p>=b.size()) throw std::runtime_error("bad DNS name");
            unsigned n=b[p++];
            if((n&0xc0)==0xc0) {
                if(p>=b.size()) throw std::runtime_error("bad pointer");
                size_t target=((n&63)<<8)|b[p++];
                if(target>=p-2) throw std::runtime_error("invalid compression pointer");
                if(!jumped) pos=p;
                jumped=true; p=target; continue;
            }
            if(n==0) { if(!jumped) pos=p; return out; }
            if(n>63 || p+n>b.size() || out.size()+n+1>254) throw std::runtime_error("bad label");
            // Length-prefixed key avoids ambiguity between labels containing dots.
            out.push_back(char(n));
            for(unsigned j=0;j<n;++j) { unsigned char c=b[p++]; out.push_back(char(std::tolower(c))); }
        }
        throw std::runtime_error("compression loop");
    }
    struct Question { std::string key, display; uint16_t type, cls; size_t end; };
    static Question question(const Bytes& b) {
        if(b.size()<12 || u16(b,4)!=1) throw std::runtime_error("expected one question");
        size_t p=12; auto n=name(b,p); auto t=u16(b,p), c=u16(b,p+2); p+=4;
        std::string display;
        for(size_t i=0;i<n.size();) { unsigned len=uint8_t(n[i++]); if(!display.empty()) display+='.'; display+=n.substr(i,len); i+=len; }
        return {n+char(0)+char(t>>8)+char(t)+char(c>>8)+char(c),display,t,c,p};
    }
    struct TTL { size_t offset; uint32_t seconds; };
    // Only cache complete positive answers. Use minimum TTL of all records.
    static std::vector<TTL> ttls(const Bytes& b) {
        auto q=question(b); size_t p=q.end; std::vector<TTL> result;
        for(int section=0;section<3;++section) {
            unsigned count=u16(b,6+2*section);
            for(unsigned i=0;i<count;++i) {
                name(b,p); auto type=u16(b,p); auto ttl=u32(b,p+4); auto len=u16(b,p+8);
                if(type!=41) result.push_back({p+4,ttl}); // OPT's field is not a TTL
                p+=10+len; if(p>b.size()) throw std::runtime_error("truncated record");
            }
        }
        if(p!=b.size()) throw std::runtime_error("unexpected trailing data");
        return result;
    }
    static Bytes error(const Bytes& query,uint16_t rcode) {
        Bytes b(12,0); if(query.size()>=2) put16(b,0,u16(query,0));
        uint16_t rd=query.size()>=4 ? u16(query,2)&0x0100 : 0;
        put16(b,2,0x8080|rd|rcode);
        try { auto q=question(query); b.insert(b.end(),query.begin()+12,query.begin()+q.end); put16(b,4,1); } catch(...) {}
        return b;
    }
};

class Cache {
    struct Entry { Bytes packet; std::vector<PacketParser::TTL> ttls; Clock::time_point saved,expires; };
    std::unordered_map<std::string,Entry> entries;
    std::shared_mutex mutex;
public:
    bool get(const std::string& key,uint16_t id,Bytes& response) {
        std::shared_lock<std::shared_mutex> lock(mutex); // many readers can proceed together
        auto it=entries.find(key); auto now=Clock::now();
        if(it==entries.end() || now>=it->second.expires) return false;
        auto& e=it->second; response=e.packet;
        auto age=std::chrono::duration_cast<std::chrono::seconds>(now-e.saved).count();
        for(auto t:e.ttls) PacketParser::put32(response,t.offset,age>=t.seconds?0:t.seconds-uint32_t(age));
        PacketParser::put16(response,0,id); return true;
    }
    void evictExpired() {
        std::unique_lock<std::shared_mutex> lock(mutex);
        auto now=Clock::now();
        for(auto it=entries.begin();it!=entries.end();) {
            if(now>=it->second.expires) it=entries.erase(it); else ++it;
        }
    }
    void put(const std::string& key,const Bytes& response) {
        auto flags=PacketParser::u16(response,2);
        if((flags&0x020f) || !PacketParser::u16(response,6)) return;
        auto ttls=PacketParser::ttls(response); if(ttls.empty()) return;
        uint32_t ttl=ttls[0].seconds; for(auto t:ttls) ttl=std::min(ttl,t.seconds);
        if(!ttl) return;
        auto now=Clock::now();
        std::unique_lock<std::shared_mutex> lock(mutex);
        entries.insert_or_assign(key,Entry{response,ttls,now,now+std::chrono::seconds(ttl)});
    }
};

class ThreadPool {
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> jobs;
    std::mutex mutex; std::condition_variable cv; bool stopping=false;
public:
    explicit ThreadPool(size_t n) {
        for(size_t i=0;i<n;++i) workers.emplace_back([this]{
            while(true) {
                std::function<void()> job;
                { std::unique_lock<std::mutex> lock(mutex);
                  cv.wait(lock,[this]{return stopping||!jobs.empty();});
                  if(stopping&&jobs.empty()) return;
                  job=std::move(jobs.front()); jobs.pop(); }
                job(); // don't hold queue lock during network I/O
            }
        });
    }
    void submit(std::function<void()> job) {
        { std::lock_guard<std::mutex> lock(mutex); jobs.push(std::move(job)); }
        cv.notify_one();
    }
    ~ThreadPool() {
        { std::lock_guard<std::mutex> lock(mutex); stopping=true; }
        cv.notify_all(); for(auto& t:workers) t.join();
    }
};

struct Socket { int fd; explicit Socket(int f):fd(f){} ~Socket(){if(fd>=0) close(fd);} Socket(const Socket&)=delete; };
class UpstreamPool {
    std::vector<sockaddr_in> servers;
public:
    explicit UpstreamPool(const std::vector<std::string>& addresses) {
        for(auto a:addresses) {
            sockaddr_in s{}; s.sin_family=AF_INET; auto colon=a.find(':');
            int port=colon==std::string::npos?53:std::stoi(a.substr(colon+1));
            if(port<1||port>65535||inet_pton(AF_INET,a.substr(0,colon).c_str(),&s.sin_addr)!=1) throw std::runtime_error("invalid upstream");
            s.sin_port=htons(port); servers.push_back(s);
        }
    }
    Bytes resolve(Bytes query,const std::string& key) const {
        auto original=PacketParser::u16(query,0);
        // Separate connected UDP socket per attempt; random ID and OS-selected source port.
        thread_local std::random_device rng;
        auto deadline=Clock::now()+std::chrono::milliseconds(2200);
        for(auto& server:servers) {
            Socket sock(socket(AF_INET,SOCK_DGRAM,0)); if(sock.fd<0) continue;
            if(connect(sock.fd,reinterpret_cast<const sockaddr*>(&server),sizeof(server))<0) continue;
            uint16_t id=uint16_t(rng()); PacketParser::put16(query,0,id);
            if(send(sock.fd,query.data(),query.size(),0)!=ssize_t(query.size())) continue;
            auto attempt=std::min(deadline,Clock::now()+std::chrono::milliseconds(1000));
            while(Clock::now()<attempt) {
                int ms=int(std::chrono::duration_cast<std::chrono::milliseconds>(attempt-Clock::now()).count());
                pollfd p{sock.fd,POLLIN,0}; if(poll(&p,1,std::max(1,ms))<=0) break;
                Bytes response(65535); auto n=recv(sock.fd,response.data(),response.size(),0); if(n<12) break;
                response.resize(size_t(n));
                try {
                    auto flags=PacketParser::u16(response,2);
                    if(PacketParser::u16(response,0)!=id || !(flags&0x8000) || (flags&0x7800) || PacketParser::question(response).key!=key) continue;
                    auto rcode=flags&15; if(rcode==2||rcode==5) break; // SERVFAIL or REFUSED: try next server
                    if(!(flags&0x0200)) PacketParser::ttls(response); // validate record boundaries
                    PacketParser::put16(response,0,original); return response;
                } catch(...) { continue; }
            }
            if(Clock::now()>=deadline) break;
        }
        return PacketParser::error(query,2); // caller restores original ID
    }
};

class QueryLog {
    sqlite3* db=nullptr; std::mutex mutex;
public:
    explicit QueryLog(const std::string& path) {
        if(sqlite3_open(path.c_str(),&db)!=SQLITE_OK) {sqlite3_close(db); throw std::runtime_error("cannot open database");}
        const char* sql="CREATE TABLE IF NOT EXISTS queries(id INTEGER PRIMARY KEY, time TEXT DEFAULT CURRENT_TIMESTAMP, domain TEXT, cache_hit INTEGER, latency_ms INTEGER, rcode INTEGER);";
        if(sqlite3_exec(db,sql,nullptr,nullptr,nullptr)!=SQLITE_OK) {sqlite3_close(db); throw std::runtime_error("cannot create log table");}
    }
    ~QueryLog(){sqlite3_close(db);}
    void add(const std::string& domain,bool hit,long ms,int rcode) {
        std::lock_guard<std::mutex> lock(mutex); // serialize writes on the shared SQLite connection
        sqlite3_stmt* s=nullptr;
        if(sqlite3_prepare_v2(db,"INSERT INTO queries(domain,cache_hit,latency_ms,rcode) VALUES(?,?,?,?)",-1,&s,nullptr)!=SQLITE_OK) return;
        sqlite3_bind_text(s,1,domain.data(),int(domain.size()),SQLITE_TRANSIENT);
        sqlite3_bind_int(s,2,hit); sqlite3_bind_int64(s,3,ms); sqlite3_bind_int(s,4,rcode);
        if(sqlite3_step(s)!=SQLITE_DONE) std::cerr<<"log write failed\n";
        sqlite3_finalize(s);
    }
    void stats() {
        sqlite3_stmt* s=nullptr;
        if(sqlite3_prepare_v2(db,"SELECT COUNT(*),COALESCE(SUM(cache_hit),0),COALESCE(AVG(latency_ms),0),COALESCE(SUM(rcode!=0),0) FROM queries",-1,&s,nullptr)!=SQLITE_OK) throw std::runtime_error("stats query failed");
        if(sqlite3_step(s)==SQLITE_ROW) std::cout<<"Queries: "<<sqlite3_column_int64(s,0)<<"\nCache hits: "<<sqlite3_column_int64(s,1)<<"\nAverage latency (ms): "<<sqlite3_column_double(s,2)<<"\nNonzero DNS response codes: "<<sqlite3_column_int64(s,3)<<'\n';
        sqlite3_finalize(s);
    }
};

class Resolver {
    Cache cache; UpstreamPool upstream; QueryLog log;
public:
    Resolver(const std::vector<std::string>& servers,const std::string& path):upstream(servers),log(path){}
    Bytes handle(const Bytes& query) {
        auto start=Clock::now(); Bytes response; std::string domain="?"; bool hit=false;
        try {
            auto q=PacketParser::question(query); domain=q.display;
            auto flags=PacketParser::u16(query,2);
            // Deliberately narrow: ordinary recursive IN UDP queries, no EDNS or DNSSEC options.
            if((flags&~0x0100)||q.cls!=1||PacketParser::u16(query,6)||PacketParser::u16(query,8)||PacketParser::u16(query,10)||q.end!=query.size()) response=PacketParser::error(query,4);
            else {
                auto id=PacketParser::u16(query,0); // Preserve original question bytes (including letter case) on cached replies.
                auto key=std::string(query.begin()+12,query.end())+char(bool(flags&0x0100));
                cache.evictExpired(); hit=cache.get(key,id,response);
                if(!hit) { response=upstream.resolve(query,q.key); PacketParser::put16(response,0,id); cache.put(key,response); }
            }
        } catch(...) { response=PacketParser::error(query,1); }
        auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-start).count();
        log.add(domain,hit,ms,PacketParser::u16(response,2)&15); return response;
    }
};

volatile std::sig_atomic_t running=1;
void stop(int){running=0;}
int main(int argc,char** argv) {
    try {
        if(argc>1 && std::string(argv[1])=="--stats") { QueryLog log(argc>2?argv[2]:"queries.db"); log.stats(); return 0; }
        int port=argc>1?std::stoi(argv[1]):5353; if(port<1||port>65535) throw std::runtime_error("invalid port");
        std::vector<std::string> upstreams; for(int i=2;i<argc;++i) upstreams.emplace_back(argv[i]);
        if(upstreams.empty()) upstreams={"1.1.1.1","8.8.8.8"};
        Socket listener(socket(AF_INET,SOCK_DGRAM,0)); if(listener.fd<0) throw std::runtime_error("socket failed");
        sockaddr_in local{}; local.sin_family=AF_INET; local.sin_port=htons(port); local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if(bind(listener.fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))<0) throw std::runtime_error("bind failed");
        Resolver resolver(upstreams,"queries.db"); ThreadPool workers(4); // destroyed before resolver and socket
        std::signal(SIGINT,stop); std::signal(SIGTERM,stop);
        std::cout<<"DNSense listening on 127.0.0.1:"<<port<<std::endl;
        while(running) {
            pollfd p{listener.fd,POLLIN,0}; if(poll(&p,1,200)<=0) continue;
            Bytes query(65535); sockaddr_in client{}; socklen_t len=sizeof(client);
            auto n=recvfrom(listener.fd,query.data(),query.size(),0,reinterpret_cast<sockaddr*>(&client),&len); if(n<0) continue;
            query.resize(size_t(n));
            workers.submit([&,query=std::move(query),client,len]{
                auto response=resolver.handle(query);
                sendto(listener.fd,response.data(),response.size(),0,reinterpret_cast<const sockaddr*>(&client),len);
            });
        }
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
