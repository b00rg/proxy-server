import socket
import threading
import time

CACHE_TTL = 60
MAX_CACHE_SIZE = 50
MAX_CACHE_BYTES = 1_000_000
BUFFER_SIZE = 4096
SOCKET_TIMEOUT = 30
THREAD_POOL_SIZE = 20
TIMING_LOG = "timing_log.txt"

def parse_url(url: str):
    scheme = "http"
    if "://" in url:
        scheme, url = url.split("://", 1)
    default_port = 443 if scheme == "https" else 80
    if "/" in url:
        authority, path = url.split("/", 1)
        path = "/" + path
    else:
        authority, path = url, "/"

    if ":" in authority:
        host, port_str = authority.rsplit(":", 1)
        port = int(port_str)
    else:
        host, port = authority, default_port

    return scheme, host, port, path

class ServerProxy:
    def __init__(self, host="127.0.0.1", port=8888, cache=None, blocklist=None, lock=None):
        self.host = host
        self.port = port
        self.cache = cache if cache is not None else {}
        self.blocklist = blocklist if blocklist is not None else set()
        self.lock = lock if lock is not None else threading.Lock()

class TCPServer(ServerProxy):
    def start_server(self):
        http_handler = Http_Handler( cache=self.cache, blocklist=self.blocklist, lock=self.lock)
        https_handler = Https_Handler(cache=self.cache, blocklist=self.blocklist, lock=self.lock)
        self._work = []
        self._work_cond = threading.Condition()

        for _ in range(THREAD_POOL_SIZE):
            t = threading.Thread(
                target=self._worker,
                args=(http_handler, https_handler),
                daemon=True,
            )
            t.start()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(10)
            print(f"[PROXY] Listening on {self.host}:{self.port}")
            print(f"[PROXY] Set your browser proxy to 127.0.0.1:{self.port}")

            while True:
                try:
                    conn, addr = sock.accept()
                    with self._work_cond:
                        self._work.append((conn, addr))
                        self._work_cond.notify()
                except Exception as e:
                    print(f"[ERROR] Accept failed: {e}")

    def _worker(self, http_handler, https_handler):
        while True:
            with self._work_cond:
                while not self._work:
                    self._work_cond.wait()
                conn, addr = self._work.pop(0)
            self._handle_client(conn, addr, http_handler, https_handler)

    def _handle_client(self, conn, addr, http_handler, https_handler):
        try:
            raw = conn.recv(BUFFER_SIZE)
            if not raw:
                conn.close()
                return

            method, host, port, path = Request_Parser.parse(raw)

            if method == "CONNECT":
                print(f"[{time.strftime('%H:%M:%S')}] {addr[0]} — {method} {path}")
                https_handler.handle(conn, host, port)
            else:
                print(f"[{time.strftime('%H:%M:%S')}] {addr[0]} — {method} {host}{path}")
                http_handler.handle(conn, host, port, path, raw)

        except Exception as e:
            print(f"[ERROR] Client handler failed: {e}")
            conn.close()

class Request_Parser:
    @staticmethod
    def parse(raw_request: bytes):
        CRLF = "\r\n"
        text = raw_request.decode("utf-8", errors="replace")

        try:
            start_line, header_block = text.split(CRLF, 1)
        except ValueError:
            raise ValueError("Malformed request: missing CRLF")

        parts = start_line.split(" ")
        if len(parts) != 3:
            raise ValueError("Bad request line")

        method, target, _ = parts
        port = 443 if method.upper() == "CONNECT" else 80
        host = None
        path = target

        if method.upper() == "CONNECT":
            if ":" in target:
                host, port_str = target.split(":", 1)
                port = int(port_str)
            else:
                host = target

        elif target.startswith("http://") or target.startswith("https://"):
            _, host, port, path = parse_url(target)

        else:
            path = target
            for line in header_block.split(CRLF):
                if line.lower().startswith("host:"):
                    host_header = line.split(":", 1)[1].strip()
                    if ":" in host_header:
                        host, port_str = host_header.split(":", 1)
                        port = int(port_str)
                    else:
                        host = host_header
                    break

        return method, host, port, path
    
class Http_Handler(ServerProxy):
    def __init__(self, cache=None, blocklist=None, lock=None):
        super().__init__(cache=cache, blocklist=blocklist, lock=lock)

    def fetch_from_server(self, host, port, request_data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            try:
                socket.inet_aton(host)
                ip = host
            except socket.error:
                ip = socket.gethostbyname(host)
            sock.connect((ip, port))
            sock.sendall(request_data)
            response = bytearray()
            try:
                while True:
                    chunk = sock.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    response.extend(chunk)
            except socket.timeout:
                pass
            return bytes(response)

    def handle(self, conn, host, port, path, raw_request):
        cache_key = f"{host}{path}"

        with self.lock:
            is_blocked = host in self.blocklist
        if is_blocked:
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by proxy.")
            conn.close()
            print(f"[BLOCKED] {host}")
            return

        with self.lock:
            cached = self.cache.get(cache_key)
        if cached:
            ts, cached_response = cached
            age = time.time() - ts
            if age < CACHE_TTL:
                t0      = time.time()
                conn.sendall(cached_response)
                elapsed = time.time() - t0
                print(f"[CACHE HIT ] {cache_key} — served in {elapsed:.4f}s (age {age:.0f}s)")
                self._log_timing(cache_key, "HIT", elapsed)
                conn.close()
                return

        raw_request = self._set_connection_close(raw_request)
        try:
            t0       = time.time()
            response = self.fetch_from_server(host, port, raw_request)
            elapsed  = time.time() - t0
            print(f"[CACHE MISS] {cache_key} — fetched in {elapsed:.4f}s ({len(response)} bytes)")
            self._log_timing(cache_key, "MISS", elapsed)
        except Exception as e:
            print(f"[ERROR] {host}: {e}")
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\nProxy could not reach the server.")
            conn.close()
            return

        if len(response) <= MAX_CACHE_BYTES:
            with self.lock:
                if len(self.cache) >= MAX_CACHE_SIZE:
                    oldest = min(self.cache, key=lambda k: self.cache[k][0])
                    del self.cache[oldest]
                self.cache[cache_key] = (time.time(), response)

        conn.sendall(response)
        conn.close()

    def _set_connection_close(self, raw_request):
        lines  = raw_request.split(b"\r\n")
        output = []
        found  = False
        for line in lines:
            if line.lower().startswith(b"connection:") or line.lower().startswith(b"proxy-connection:"):
                output.append(b"Connection: close")
                found = True
            elif line.lower().startswith(b"keep-alive:"):
                continue
            else:
                output.append(line)
        if not found:
            output.insert(1, b"Connection: close")
        return b"\r\n".join(output)

    def _log_timing(self, url, hit_or_miss, elapsed):
        with open(TIMING_LOG, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}, {hit_or_miss}, {elapsed:.4f}s, {url}\n")

class Https_Handler(ServerProxy):
    def __init__(self, cache=None, blocklist=None, lock=None):
        super().__init__(cache=cache, blocklist=blocklist, lock=lock)

    def handle(self, conn, host, port):
        with self.lock:
            is_blocked = host in self.blocklist
        if is_blocked:
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by proxy.")
            conn.close()
            print(f"[BLOCKED] {host}")
            return

        try:
            try:
                socket.inet_aton(host)
                ip = host
            except socket.error:
                ip = socket.gethostbyname(host)
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(SOCKET_TIMEOUT)
            remote.connect((ip, port))
        except Exception as e:
            print(f"[ERROR] HTTPS connect failed {host}:{port} — {e}")
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            conn.close()
            return

        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        def forward(src, dst):
            try:
                while True:
                    data = src.recv(BUFFER_SIZE)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                src.close()
                dst.close()

        threading.Thread(target=forward, args=(conn,   remote), daemon=True).start()
        threading.Thread(target=forward, args=(remote, conn),   daemon=True).start()

class Management_Console:
    def __init__(self, blocklist, cache, lock):
        self.blocklist = blocklist
        self.cache     = cache
        self.lock      = lock

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        print("[CONSOLE] Management console ready. Type 'help' for commands.")
        while True:
            try:
                cmd = input(">> ").strip().split()
            except EOFError:
                break
            if not cmd:
                continue

            action = cmd[0].lower()

            if action == "block" and len(cmd) > 1:
                with self.lock:
                    self.blocklist.add(cmd[1])
                print(f"[CONSOLE] Blocked: {cmd[1]}")
            elif action == "unblock" and len(cmd) > 1:
                with self.lock:
                    self.blocklist.discard(cmd[1])
                print(f"[CONSOLE] Unblocked: {cmd[1]}")
            elif action == "show" and len(cmd) > 1 and cmd[1] == "blocklist":
                with self.lock:
                    bl = set(self.blocklist)
                print("\n".join(f"  {h}" for h in sorted(bl)) if bl else "  (empty)")
            elif action == "show" and len(cmd) > 1 and cmd[1] == "cache":
                with self.lock:
                    snapshot = dict(self.cache)
                if snapshot:
                    print(f"  {'URL':<55} {'SIZE':>8}  AGE")
                    for k, (ts, v) in snapshot.items():
                        print(f"  {k:<55} {len(v):>6}B  {time.time()-ts:.0f}s ago")
                else:
                    print("  (cache is empty)")

            elif action == "clear" and len(cmd) > 1 and cmd[1] == "cache":
                with self.lock:
                    self.cache.clear()
                print("[CONSOLE] Cache cleared.")
            elif action == "stats":
                self._print_stats()
            elif action == "help":
                print("Commands:")
                print("1. block <host>     - block a host")
                print("2. unblock <host>   - unblock a host")
                print("3. show blocklist   - list blocked hosts")
                print("4. show cache       - list cached responses")
                print("5. clear cache      - empty the cache")
                print("6. stats            - show timing statistics")
                print("7. help             - show this message")
            else:
                print("  Unknown command. Type 'help'.")

    def _print_stats(self):
        """Reads timing_log.txt and prints hit/miss summary with speedup ratio."""
        try:
            hits, misses          = 0, 0
            hit_times, miss_times = [], []
            with open(TIMING_LOG, "r") as f:
                for line in f:
                    parts = line.strip().split(", ")
                    if len(parts) < 3:
                        continue
                    kind    = parts[1]
                    elapsed = float(parts[2].replace("s", ""))
                    if kind == "HIT":
                        hits += 1
                        hit_times.append(elapsed)
                    elif kind == "MISS":
                        misses += 1
                        miss_times.append(elapsed)

            total = hits + misses
            print(f"\n  ── Cache Statistics ──────────────────────")
            print(f"  Total requests  : {total}")
            print(f"  Cache hits      : {hits}  ({100*hits//total if total else 0}%)")
            print(f"  Cache misses    : {misses}  ({100*misses//total if total else 0}%)")
            if hit_times:
                print(f"  Avg HIT time    : {sum(hit_times)/len(hit_times):.4f}s")
            if miss_times:
                print(f"  Avg MISS time   : {sum(miss_times)/len(miss_times):.4f}s")
            if hit_times and miss_times:
                avg_hit  = sum(hit_times)  / len(hit_times)
                avg_miss = sum(miss_times) / len(miss_times)
                if avg_hit > 0:
                    ratio = avg_miss / avg_hit
                    print(f"  Cache is {ratio:.1f}x faster than origin")
                else:
                    print(f"  Cache is effectively instant (HIT time < 0.0001s)")
            print(f"  ──────────────────────────────────────────\n")
        except FileNotFoundError:
            print("  No timing data yet — make some HTTP requests first.")

if __name__ == "__main__":
    shared_cache     = {}
    shared_blocklist = set()
    shared_lock      = threading.Lock()
    Management_Console(shared_blocklist, shared_cache, shared_lock).start()
    TCPServer(
        host      = "127.0.0.1",
        port      = 8888,
        cache     = shared_cache,
        blocklist = shared_blocklist,
        lock      = shared_lock,
    ).start_server()
