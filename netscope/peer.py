"""Dedicated measurement peer. The Python standard library is sufficient on the remote host."""

import argparse
import hashlib
import hmac
import os
import secrets
import socket
import threading
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BLOCK = bytes(64 * 1024)
SIZE = 4 * 1024 * 1024
DEADLINE = 15
SERVICE = "netscope-peer/1"


def signature(key, text):
    return hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()


class PeerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, key):
        self.key = key
        self.slots = threading.BoundedSemaphore(2)
        super().__init__(address, PeerHandler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, address)

    def process_request_thread(self, request, address):
        # A wall-clock deadline also covers slow headers, uploads and blocked writes.
        def interrupt_io():
            with suppress(OSError):
                request.shutdown(socket.SHUT_RDWR)

        deadline = threading.Timer(DEADLINE, interrupt_io)
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, address)
        finally:
            deadline.cancel()
            self.slots.release()

    def handle_error(self, request, client_address):
        import sys

        if not isinstance(sys.exception(), OSError):
            super().handle_error(request, client_address)


class PeerHandler(BaseHTTPRequestHandler):
    server: PeerServer

    def log_message(self, format, *args):
        pass

    def reply(self, code, body=b"", **headers):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        stamp = self.headers.get("X-NetScope-Time", "")
        nonce = self.headers.get("X-NetScope-Nonce", "")
        if not stamp.isascii() or not stamp.isdigit() or len(stamp) > 12 or len(nonce) != 32:
            self.reply(401)
            return False
        self.challenge = f"{self.command} {self.path} {stamp} {nonce}"
        expected = signature(self.server.key, self.challenge)
        received = self.headers.get("X-NetScope-Auth", "").encode("latin1")
        if abs(time.time() - int(stamp)) > 60 or not hmac.compare_digest(expected.encode(), received):
            self.reply(401)
            return False
        return True

    def do_GET(self):
        if not self.authorized():
            return
        if self.path == "/v1/ping":
            proof = signature(self.server.key, f"reply {self.challenge}")
            self.reply(200, SERVICE.encode(), **{"X-NetScope-Proof": proof})
        elif self.path == "/v1/download":
            self.send_response(200)
            self.send_header("Content-Length", str(SIZE))
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            for _ in range(SIZE // len(BLOCK)):
                self.wfile.write(BLOCK)
        else:
            self.reply(404)

    def do_POST(self):
        if not self.authorized():
            return
        if self.path != "/v1/upload":
            self.reply(404)
            return
        if self.headers.get("Content-Length") != str(SIZE) or self.headers.get("Transfer-Encoding"):
            self.reply(413)
            return
        remaining = SIZE
        while remaining:
            chunk = self.rfile.read(min(remaining, len(BLOCK)))
            if not chunk:
                self.reply(400)
                return
            remaining -= len(chunk)
        self.reply(200, str(SIZE).encode())


def main():
    parser = argparse.ArgumentParser(description="NetScope 受控 HTTP 测速端点")
    parser.add_argument("--bind", default="127.0.0.1", help="指定本机测试接口的监听地址")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    key = os.environ.get("NETSCOPE_PEER_TOKEN")
    if not key:
        key = secrets.token_urlsafe(24)
        print(f"本次配对密钥 / Pairing key: {key}", flush=True)
    if not 12 <= len(key) <= 128:
        parser.error("NETSCOPE_PEER_TOKEN 长度须为 12–128 个字符")
    if ":" in args.bind:
        PeerServer.address_family = socket.AF_INET6
    with PeerServer((args.bind, args.port), key) as server:
        print(f"NetScope peer listening on {args.bind}, port {server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
