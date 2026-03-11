import unittest
import threading
import socket
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import project1
from project1 import Request_Parser, Http_Handler


def make_pair():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.connect(("127.0.0.1", srv.getsockname()[1]))
    conn, _ = srv.accept()
    srv.close()
    return conn, cli


def make_handler(cache=None, blocklist=None):
    cache     = cache     if cache     is not None else {}
    blocklist = blocklist if blocklist is not None else set()
    lock      = threading.Lock()
    return Http_Handler(cache=cache, blocklist=blocklist, lock=lock)


class TestRequestParser(unittest.TestCase):
    def test_http_full_url(self):
        m, h, p, path = Request_Parser.parse(b"GET http://example.com/foo HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertEqual((m, h, p, path), ("GET", "example.com", 80, "/foo"))

    def test_http_query_string(self):
        _, _, _, path = Request_Parser.parse(b"GET http://example.com/s?q=hi HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertEqual(path, "/s?q=hi")

    def test_connect(self):
        m, h, p, _ = Request_Parser.parse(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertEqual((m, h, p), ("CONNECT", "example.com", 443))

    def test_relative_path(self):
        _, h, _, path = Request_Parser.parse(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertEqual((h, path), ("example.com", "/index.html"))

    def test_malformed_raises(self):
        with self.assertRaises(Exception):
            Request_Parser.parse(b"NOTVALID")


class TestBlocklist(unittest.TestCase):
    def test_blocked_returns_403(self):
        h = make_handler(blocklist={"blocked.com"})
        conn, cli = make_pair()
        h.handle(conn, "blocked.com", 80, "/", b"GET http://blocked.com/ HTTP/1.1\r\n\r\n")
        self.assertIn("403", cli.recv(4096).decode())
        cli.close()

    def test_unblocked_not_in_set(self):
        bl = {"example.com"}
        bl.discard("example.com")
        self.assertNotIn("example.com", bl)

class TestCache(unittest.TestCase):
    FAKE = b"HTTP/1.1 200 OK\r\n\r\nHello"
    RAW  = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"

    def test_hit_returns_cached(self):
        cache = {"example.com/": (time.time(), self.FAKE)}
        h = make_handler(cache=cache)
        conn, cli = make_pair()
        h.handle(conn, "example.com", 80, "/", self.RAW)
        self.assertEqual(cli.recv(4096), self.FAKE)
        cli.close()

    def test_hit_is_fast(self):
        cache = {"example.com/": (time.time(), self.FAKE * 100)}
        h = make_handler(cache=cache)
        conn, cli = make_pair()
        t0 = time.time()
        h.handle(conn, "example.com", 80, "/", self.RAW)
        self.assertLess(time.time() - t0, 0.05)
        cli.close()

    def test_expired_entry_age(self):
        cache = {"example.com/": (time.time() - project1.CACHE_TTL - 1, self.FAKE)}
        ts, _ = cache["example.com/"]
        self.assertGreater(time.time() - ts, project1.CACHE_TTL)

    def test_large_response_not_cached(self):
        cache = {}
        oversized = b"x" * (project1.MAX_CACHE_BYTES + 1)
        if len(oversized) <= project1.MAX_CACHE_BYTES:
            cache["big/"] = (time.time(), oversized)
        self.assertNotIn("big/", cache)

class TestThreading(unittest.TestCase):
    def test_concurrent_cache_hits(self):
        cache = {"example.com/": (time.time(), b"HTTP/1.1 200 OK\r\n\r\nHi")}
        h = make_handler(cache=cache)
        results = []

        def req():
            conn, cli = make_pair()
            h.handle(conn, "example.com", 80, "/", b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            results.append(cli.recv(4096))
            cli.close()

        threads = [threading.Thread(target=req) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(len(results), 5)

    def test_lock_thread_safe(self):
        lock  = threading.Lock()
        count = [0]
        def inc():
            for _ in range(1000):
                with lock: count[0] += 1
        threads = [threading.Thread(target=inc) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(count[0], 10000)

class TestConnectionClose(unittest.TestCase):
    def setUp(self):
        self.h = make_handler()

    def test_keep_alive_replaced(self):
        r = self.h._set_connection_close(b"GET / HTTP/1.1\r\nConnection: keep-alive\r\nHost: x\r\n\r\n")
        self.assertIn(b"Connection: close", r)
        self.assertNotIn(b"keep-alive", r)

    def test_added_if_missing(self):
        r = self.h._set_connection_close(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertIn(b"Connection: close", r)


if __name__ == "__main__":
    unittest.main(verbosity=2)