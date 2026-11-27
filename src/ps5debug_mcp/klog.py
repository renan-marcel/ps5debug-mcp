"""Background TCP 3232 /dev/klog ring-buffer reader for ps5debug-NG."""
from __future__ import annotations

import socket
import threading
from collections import deque
from typing import Optional

KLOG_PORT = 3232


class KlogReader:
    """Connects to ps5debug-NG's klog forwarder (TCP 3232) and keeps recent lines."""

    def __init__(self, max_lines: int = 2000) -> None:
        self._max_lines = max_lines
        self._lines: deque[str] = deque(maxlen=max_lines)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._host: Optional[str] = None
        self._port: int = KLOG_PORT
        self._error: Optional[str] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def last_error(self) -> Optional[str]:
        return self._error

    def start(self, host: str, port: int = KLOG_PORT) -> None:
        self.stop()
        self._host = host
        self._port = port
        self._error = None
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="ps5-klog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1.5)
            self._thread = None

    def push_line(self, line: str) -> None:
        with self._lock:
            self._lines.append(line)

    def tail(self, count: int = 50, filter_text: Optional[str] = None) -> list[str]:
        with self._lock:
            items = list(self._lines)
        if filter_text:
            needle = filter_text.lower()
            items = [line for line in items if needle in line.lower()]
        return items[-max(1, count):]

    def _run(self) -> None:
        buf = bytearray()
        try:
            sock = socket.create_connection((self._host, self._port), timeout=5.0)
            sock.settimeout(0.5)
            self._sock = sock
            while not self._stop.is_set():
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf.extend(chunk)
                while b"\n" in buf:
                    idx = buf.index(b"\n")
                    raw = bytes(buf[:idx]).rstrip(b"\r")
                    del buf[: idx + 1]
                    self.push_line(raw.decode("utf-8", "replace"))
        except OSError as exc:
            if not self._stop.is_set():
                self._error = str(exc)
        finally:
            if buf:
                self.push_line(bytes(buf).decode("utf-8", "replace").rstrip("\r\n"))
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
