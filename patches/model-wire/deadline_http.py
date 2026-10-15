"""Complete HTTP deadlines, including slow body streams; no request retries."""
import http.client
import json
import math
import socket
import ssl
import subprocess
import sys
import threading
import time


class HTTPDeadline(TimeoutError):
    pass


def resolve_origin(host, port, timeout=10):
    code = 'import socket,json,sys;print(json.dumps([(a,b,c,e)for a,b,c,d,e in socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)]))'
    result = subprocess.run([sys.executable, '-c', code, host, str(port)], capture_output=True,
                            text=True, check=True, timeout=timeout)
    addresses = json.loads(result.stdout)
    if not addresses:
        raise OSError('No addresses for fixed origin')
    return addresses


class DeadlineConnection(http.client.HTTPConnection):
    def __init__(self, host, port, addresses, timeout, tls_context=None, verify_peer=None):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('Positive finite total HTTP timeout required')
        super().__init__(host, port, timeout=timeout)
        self.addresses = addresses
        self.tls_context = tls_context
        self.verify_peer = verify_peer
        self.deadline = time.monotonic() + timeout
        self.expired = threading.Event()
        self.sockets = []
        self.socket_lock = threading.Lock()
        self.timer = threading.Timer(timeout, self.abort)
        self.timer.daemon = True
        self.timer.start()

    def remaining(self):
        left = self.deadline - time.monotonic()
        if self.expired.is_set() or left <= 0:
            raise HTTPDeadline('Complete HTTP deadline expired')
        return left

    def abort(self):
        self.expired.set()
        with self.socket_lock:
            for sock in self.sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()

    def register(self, sock):
        with self.socket_lock:
            self.sockets.append(sock)
        self.remaining()

    def connect(self):
        last = None
        for family, kind, protocol, address in self.addresses:
            self.remaining()
            raw = socket.socket(family, kind, protocol)
            self.register(raw)
            try:
                raw.settimeout(self.remaining())
                raw.connect(tuple(address))
                self.sock = raw
                if self.tls_context:
                    tls = self.tls_context.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
                    self.sock = tls
                    self.register(tls)
                    tls.settimeout(self.remaining())
                    tls.do_handshake()
                    self.verify_peer(tls.getpeercert(binary_form=True))
                self.remaining()
                return
            except ssl.SSLCertVerificationError:
                self.close()
                raise
            except OSError as error:
                last = error
                raw.close()
                self.sock = None
                self.remaining()
        raise OSError('Fixed origin connection failed') from last

    def finish(self):
        self.timer.cancel()
        self.timer.join(timeout=1)
        self.close()
        with self.socket_lock:
            for sock in self.sockets:
                sock.close()

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        expired = self.expired.is_set() or time.monotonic() >= self.deadline
        self.finish()
        if expired:
            raise HTTPDeadline('Complete HTTP deadline expired') from value
        return False
