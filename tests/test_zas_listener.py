"""Tests for lib/zas_listener.py — the TCP reverse-shell catcher.

These use real loopback sockets so they exercise the threading path
rather than a mock. Every wait polls with a deadline: fixed sleeps went
flaky under full-suite load while passing in isolation.
"""

import socket
import time

import pytest

from zas_listener import ReverseListener


def _drain(sock, timeout=1.0):
    sock.settimeout(timeout)
    try:
        return sock.recv(4096)
    except socket.timeout:
        return b""


def _wait_for(predicate, timeout=5.0, interval=0.05):
    """Poll until ``predicate()`` is truthy."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


@pytest.fixture
def listener():
    got = {"conn": 0, "data": "", "close": 0, "errors": []}
    lst = ReverseListener(
        host="127.0.0.1", port=0,
        on_connect=lambda c: got.__setitem__("conn", got["conn"] + 1),
        on_data=lambda c, t: got.__setitem__("data", got["data"] + t),
        on_close=lambda c: got.__setitem__("close", got["close"] + 1),
        on_error=lambda e: got["errors"].append(str(e)),
    )
    lst.start()
    lst._test_got = got
    yield lst
    lst.stop()


def _connect(port, attempts=4):
    """Connect with a few retries.

    On Windows an exclusive bind over a port still in TIME_WAIT can yield a
    socket that accepts the bind but never answers SYNs; a real client
    retries, so the test does too. A single failed attempt therefore does
    not fail the test — a persistent one does.
    """
    last = None
    for _ in range(attempts):
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=2)
        except OSError as e:
            last = e
            time.sleep(0.1)
    raise last


class TestLifecycle:
    def test_start_binds_a_real_port(self, listener):
        assert listener.running
        assert listener.port > 0

    def test_stop_clears_state(self, listener):
        listener.stop()
        assert not listener.running
        assert listener.client_count() == 0

    def test_start_twice_is_idempotent(self, listener):
        port = listener.port
        listener.start()
        assert listener.port == port

    def test_port_zero_picks_ephemeral(self):
        lst = ReverseListener(host="127.0.0.1", port=0)
        p = lst.start()
        try:
            assert p != 0
        finally:
            lst.stop()


class TestAcceptAndStream:
    def test_connection_is_reported(self, listener):
        s = _connect(listener.port)
        try:
            assert _wait_for(lambda: listener._test_got["conn"] == 1)
            assert listener.client_count() == 1
        finally:
            s.close()

    def test_incoming_data_reaches_callback(self, listener):
        s = _connect(listener.port)
        try:
            s.sendall(b"uid=0(root)\n")
            assert _wait_for(lambda: "uid=0(root)" in listener._test_got["data"])
        finally:
            s.close()

    def test_send_returns_to_the_client(self, listener):
        s = _connect(listener.port)
        try:
            assert _wait_for(lambda: listener.client_count() == 1)
            n = listener.send("whoami\n")
            assert n == 1
            assert b"whoami" in _drain(s)
        finally:
            s.close()

    def test_multiple_clients(self, listener):
        socks = [_connect(listener.port) for _ in range(3)]
        try:
            assert _wait_for(lambda: listener.client_count() == 3)
            assert listener.send("hi\n") == 3
        finally:
            for s in socks:
                s.close()

    def test_broadcast_is_separate_from_single(self, listener):
        s1 = _connect(listener.port)
        s2 = _connect(listener.port)
        try:
            assert _wait_for(lambda: listener.client_count() == 2)
            only = listener.clients[0]
            listener.send("to-one\n", client=only)
            got = _drain(s1) + _drain(s2)
            assert got.count(b"to-one") == 1
        finally:
            s1.close()
            s2.close()

    def test_close_callback_fires(self, listener):
        s = _connect(listener.port)
        assert _wait_for(lambda: listener.client_count() == 1)
        s.close()
        assert _wait_for(lambda: listener._test_got["close"] >= 1)
        assert listener.client_count() == 0


class TestRobustness:
    def test_callback_exception_does_not_kill_the_listener(self):
        errs = []
        lst = ReverseListener(
            host="127.0.0.1", port=0,
            on_data=lambda c, t: (_ for _ in ()).throw(RuntimeError("boom")),
            on_error=lambda e: errs.append(str(e)),
        )
        lst.start()
        s = _connect(lst.port)
        try:
            s.sendall(b"x")
            assert _wait_for(lambda: len(errs) > 0), "error callback never fired"
            assert lst.running
            lst.send("still-alive\n")
            assert b"still-alive" in _drain(s)
        finally:
            s.close()
            lst.stop()

    def test_port_conflict_raises(self):
        first = ReverseListener(host="127.0.0.1", port=0)
        first.start()
        busy = first.port
        try:
            with pytest.raises(OSError):
                clash = ReverseListener(host="127.0.0.1", port=busy)
                clash.start()
        finally:
            first.stop()

    def test_send_to_stale_client_is_harmless(self, listener):
        s = _connect(listener.port)
        assert _wait_for(lambda: listener.client_count() == 1)
        client = listener.clients[0]
        s.close()
        assert _wait_for(lambda: listener.client_count() == 0)
        # must not raise even though the socket is dead
        listener.send("late\n", client=client)

    def test_send_with_no_clients_is_zero(self, listener):
        assert listener.send("nobody\n") == 0


class TestClient:
    def test_send_accepts_str_and_bytes(self, listener):
        s = _connect(listener.port)
        try:
            assert _wait_for(lambda: listener.client_count() == 1)
            c = listener.clients[0]
            assert c.send("text\n") is None
            assert c.send(b"bytes\n") is None
            data = _drain(s)
            assert b"text" in data or b"bytes" in data
        finally:
            s.close()

    def test_close_is_idempotent(self, listener):
        s = _connect(listener.port)
        assert _wait_for(lambda: listener.client_count() == 1)
        c = listener.clients[0]
        c.close()
        c.close()  # must not raise
        s.close()
