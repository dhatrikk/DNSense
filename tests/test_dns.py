"""Offline integration tests: local fake DNS upstream, no external network needed."""
import concurrent.futures
import pathlib
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time

BIN = pathlib.Path(__file__).resolve().parents[1] / 'dnsense'

def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 0))
    return s

def query(name, ident=123):
    return struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\0' + struct.pack('!HH', 1, 1)

def ask(port, packet):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(8)
        s.sendto(packet, ('127.0.0.1', port))
        return s.recv(65535)

def header(b):
    return struct.unpack('!6H', b[:12])

with tempfile.TemporaryDirectory() as tmp, udp() as silent, udp() as upstream, udp() as reserve:
    port = reserve.getsockname()[1]
    reserve.close()
    counts = []
    stop = threading.Event()
    upstream.settimeout(.1)
    def serve():
        while not stop.is_set():
            try:
                q, client = upstream.recvfrom(65535)
            except socket.timeout:
                continue
            counts.append(q)
            # Compressed answer name points to the question at byte 12.
            reply = struct.pack('!6H', header(q)[0], 0x8180, 1, 1, 0, 0) + q[12:] + struct.pack('!HHHIH4B', 0xc00c, 1, 1, 2, 4, 192, 0, 2, 42)
            upstream.sendto(reply, client)
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    proc = subprocess.Popen([str(BIN), str(port), f'127.0.0.1:{silent.getsockname()[1]}', f'127.0.0.1:{upstream.getsockname()[1]}'], cwd=tmp, stdout=subprocess.PIPE, text=True)
    try:
        assert 'listening' in proc.stdout.readline()
        q = query('example.test', 100)
        start = time.monotonic()
        r = ask(port, q)
        assert header(r)[0] == 100 and header(r)[3] == 1 and r[-4:] == bytes([192,0,2,42])
        assert time.monotonic()-start >= .8 and len(counts)==1
        print('PASS: UDP resolution, compressed answer parsing and timeout fallback')
        r2 = ask(port, query('example.test', 200))
        assert header(r2)[0] == 200 and len(counts)==1
        print('PASS: cache hit and transaction ID replacement')
        time.sleep(1.05)
        r3 = ask(port, query('example.test', 300))
        assert struct.unpack('!I', r3[-10:-6])[0] == 1 and len(counts)==1
        time.sleep(1.05)
        ask(port, query('example.test', 400))
        assert len(counts)==2
        print('PASS: TTL countdown and expiry')
        start=time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            replies=list(pool.map(lambda i: ask(port, query(f'parallel{i}.test', i)), range(4)))
        assert all(header(r)[0]==i and header(r)[3]==1 for i,r in enumerate(replies))
        assert time.monotonic()-start<3.5
        print('PASS: four concurrent cache misses')
        assert header(ask(port,b'\x12\x34'))[1]&15==1
        print('PASS: malformed request handling')
        with sqlite3.connect(str(pathlib.Path(tmp)/'queries.db')) as db:
            total,hits=db.execute('SELECT COUNT(*), SUM(cache_hit) FROM queries').fetchone()
            assert (total,hits)==(9,2), (total,hits)
        output=subprocess.check_output([str(BIN),'--stats'],cwd=tmp,text=True)
        assert 'Queries: 9' in output and 'Cache hits: 2' in output
        print('PASS: SQLite logging and analytics')
    finally:
        proc.terminate(); proc.wait(timeout=8); stop.set(); t.join(timeout=1)
# All upstreams unavailable: local silent UDP endpoint gives reproducible timeout.
with tempfile.TemporaryDirectory() as tmp, udp() as silent, udp() as reserve:
    port=reserve.getsockname()[1]; reserve.close()
    proc=subprocess.Popen([str(BIN),str(port),f'127.0.0.1:{silent.getsockname()[1]}'],cwd=tmp,stdout=subprocess.PIPE,text=True)
    try:
        assert 'listening' in proc.stdout.readline()
        r=ask(port,query('unavailable.test', 987))
        assert header(r)[0]==987 and header(r)[1]&15==2
        print('PASS: all upstreams fail → SERVFAIL with original ID')
    finally:
        proc.terminate(); proc.wait(timeout=8)
print('All integration tests passed.')
