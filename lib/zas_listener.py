"""TCP reverse-shell listener for ZAS.

Accepts reverse-shell connections and streams them to a caller-supplied
callback. No GUI code here — the tkinter layer lives in
``core/revshell_tab.py`` and wires these callbacks to widgets.

Typical use::

    lst = ReverseListener(port=4444, on_data=print)
    lst.start()
    # ... later ...
    lst.send("id\\n")
    lst.stop()

Pairs with ``zas_revshell.payload()`` — the host/port in the generated
payload must match the listener's bind address and port.
"""

from __future__ import annotations

import socket
import threading
import time


class Client:
    """One accepted connection."""

    def __init__(self, sock: socket.socket, addr):
        self.sock = sock
        self.addr = addr
        self.opened = time.time()
        self.buffer = bytearray()

    def send(self, data) -> int:
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        return self.sock.sendall(data)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class ReverseListener:
    """A threaded TCP listener for reverse shells.

    Callbacks are invoked from worker threads — anything that touches a
    GUI must marshal to the main thread itself (tkinter's ``after``).

    Parameters
    ----------
    host : str
        Bind address. Use ``0.0.0.0`` to accept from anywhere, ``127.0.0.1``
        for a local-only test.
    port : int
        Bind port. 0 picks an ephemeral one — read ``self.port`` after
        ``start()`` to find out which.
    backlog : int
        Listen queue depth.
    on_connect : callable(Client)
    on_data : callable(Client, str)
    on_close : callable(Client)
    on_error : callable(Exception)
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 4444,
                 backlog: int = 16,
                 on_connect=None, on_data=None, on_close=None,
                 on_error=None):
        self.host = host
        self.port = port
        self.backlog = backlog

        self.on_connect = on_connect
        self.on_data = on_data
        self.on_close = on_close
        self.on_error = on_error

        self._sock = None
        self._accept_thread = None
        self._running = threading.Event()
        self._lock = threading.Lock()
        self._clients = []

    # -- lifecycle ----------------------------------------------------

    def start(self):
        """Bind, listen, and accept in a background thread.

        Raises ``OSError`` if the port is unavailable. ``self.port`` is
        updated to the real bound port when ``port=0`` was requested.
        """
        if self._running.is_set():
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Windows lets two sockets bind the same port when SO_REUSEADDR is
        # set, and then connections reach only one of them. Fail loudly
        # instead: an exclusive bind is what a shell catcher needs.
        #
        # Caveat: on Windows an exclusive bind over a port still in
        # TIME_WAIT can produce a socket that reports success but never
        # answers SYNs. That only bites rapid stop/start cycles, and the
        # symptom is obvious (nothing connects) rather than silent — so it
        # is preferred to the silent double-bind SO_REUSEADDR allows.
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(self.backlog)
        s.settimeout(1.0)  # lets the accept loop notice stop()
        self._sock = s
        self.port = s.getsockname()[1]

        self._running.set()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="zas-revshell-listen", daemon=True
        )
        self._accept_thread.start()
        return self.port

    def stop(self):
        """Stop accepting and close every client."""
        self._running.clear()
        with self._lock:
            clients = list(self._clients)
            self._clients.clear()
        for c in clients:
            self._safe_close(c)
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=3.0)
            self._accept_thread = None

    @property
    def running(self) -> bool:
        return self._running.is_set()

    @property
    def clients(self):
        with self._lock:
            return list(self._clients)

    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    # -- interaction --------------------------------------------------

    def send(self, data, client: Client = None):
        """Send to one client, or to every client when ``client`` is None.

        Returns the number of clients the data was sent to.
        """
        targets = [client] if client is not None else self.clients
        n = 0
        for c in targets:
            try:
                c.send(data)
                n += 1
            except OSError:
                self._safe_close(c)
        return n

    def close_client(self, client: Client):
        with self._lock:
            if client in self._clients:
                self._clients.remove(client)
        self._safe_close(client)

    # -- internals ----------------------------------------------------

    def _accept_loop(self):
        while self._running.is_set():
            try:
                sock, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            sock.settimeout(None)
            client = Client(sock, addr)
            with self._lock:
                self._clients.append(client)
            self._fire(self.on_connect, client)
            threading.Thread(
                target=self._read_loop, args=(client,),
                name="zas-revshell-client", daemon=True
            ).start()

    def _read_loop(self, client: Client):
        try:
            while self._running.is_set():
                try:
                    chunk = client.sock.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                client.buffer.extend(chunk)
                text = chunk.decode("utf-8", "replace")
                self._fire(self.on_data, client, text)
        finally:
            with self._lock:
                if client in self._clients:
                    self._clients.remove(client)
            self._safe_close(client)
            self._fire(self.on_close, client)

    def _safe_close(self, client: Client):
        try:
            client.close()
        except Exception:
            pass

    def _fire(self, fn, *args):
        if fn is None:
            return
        try:
            fn(*args)
        except Exception as e:  # never let a callback kill the loop
            self._fire(self.on_error, e)


# -- module-level convenience ----------------------------------------

_default = None


