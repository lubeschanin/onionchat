"""Tests for onionchat."""

import asyncio
import inspect
import re
import time

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.responses import HTMLResponse, StreamingResponse

import chat


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset global state between tests."""
    chat.messages.clear()
    chat.msg_counter = 0
    chat.last_sent.clear()
    chat.active_streams = 0
    chat.msg_event = asyncio.Event()
    yield


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=chat.app), base_url="http://test"
    ) as c:
        yield c


# --- Nickname ---


def test_make_nick_format():
    nick = chat.make_nick()
    assert chat.NICK_RE.match(nick)


def test_make_nick_unique():
    nicks = {chat.make_nick() for _ in range(50)}
    assert len(nicks) > 10


# --- Pages load ---


@pytest.mark.anyio
async def test_index(client):
    r = await client.get("/")
    assert r.status_code == 200
    assert "onionchat" in r.text
    assert "set-cookie" in r.headers


@pytest.mark.anyio
async def test_input(client):
    r = await client.get("/input")
    assert r.status_code == 200
    assert 'name="msg"' in r.text


@pytest.mark.anyio
async def test_clock(client):
    r = await client.get("/clock")
    assert r.status_code == 200
    assert "UTC" in r.text
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC", r.text)


# --- Send & receive ---


@pytest.mark.anyio
async def test_send_message(client):
    r = await client.post("/send", data={"msg": "hello"}, follow_redirects=False)
    assert r.status_code == 303
    assert len(chat.messages) == 1
    assert chat.messages[0]["text"] == "hello"


@pytest.mark.anyio
async def test_send_empty_ignored(client):
    await client.post("/send", data={"msg": "   "})
    assert len(chat.messages) == 0


@pytest.mark.anyio
async def test_send_sets_nick_cookie(client):
    r = await client.post("/send", data={"msg": "hi"}, follow_redirects=False)
    cookie = r.headers.get("set-cookie", "")
    assert "nick=" in cookie


@pytest.mark.anyio
async def test_send_preserves_existing_nick(client):
    client.cookies.set("nick", "Fox-ab12")
    await client.post("/send", data={"msg": "hi"})
    assert chat.messages[0]["nick"] == "Fox-ab12"


# --- XSS ---


@pytest.mark.anyio
async def test_xss_escaped(client):
    await client.post("/send", data={"msg": "<script>alert(1)</script>"})
    html = chat.render_msg(chat.messages[0])
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# --- Message limit ---


@pytest.mark.anyio
async def test_message_truncated(client):
    long_msg = "A" * 1000
    await client.post("/send", data={"msg": long_msg})
    assert len(chat.messages[0]["text"]) == chat.MAX_MSG_LEN


# --- Ring buffer ---


def test_ring_buffer():
    for i in range(250):
        chat.messages.append({"id": i, "nick": "X-0000", "time": "2026-01-01T00:00Z", "text": str(i)})
    assert len(chat.messages) == 200
    assert chat.messages[0]["id"] == 50


# --- Rate limiting ---


@pytest.mark.anyio
async def test_rate_limit(client):
    client.cookies.set("nick", "Wolf-aa11")
    await client.post("/send", data={"msg": "first"})
    await client.post("/send", data={"msg": "second"})
    assert len(chat.messages) == 1
    assert chat.messages[0]["text"] == "first"


@pytest.mark.anyio
async def test_rate_limit_expires(client):
    client.cookies.set("nick", "Wolf-bb22")
    await client.post("/send", data={"msg": "first"})
    chat.last_sent["Wolf-bb22"] -= chat.RATE_LIMIT
    await client.post("/send", data={"msg": "second"})
    assert len(chat.messages) == 2


# --- Nickname validation ---


@pytest.mark.anyio
async def test_invalid_cookie_gets_new_nick(client):
    client.cookies.set("nick", "<script>evil</script>")
    await client.post("/send", data={"msg": "hi"})
    assert chat.NICK_RE.match(chat.messages[0]["nick"])


@pytest.mark.anyio
async def test_too_long_cookie_gets_new_nick(client):
    client.cookies.set("nick", "A" * 100 + "-abcd")
    await client.post("/send", data={"msg": "hi"})
    assert chat.NICK_RE.match(chat.messages[0]["nick"])


# --- Clear ---


@pytest.mark.anyio
async def test_clear_wrong_secret(client):
    await client.post("/send", data={"msg": "hi"})
    await client.get("/clear?secret=wrong", follow_redirects=False)
    assert len(chat.messages) == 1


@pytest.mark.anyio
async def test_clear_correct_secret(client):
    await client.post("/send", data={"msg": "hi"})
    await client.get(f"/clear?secret={chat.CLEAR_SECRET}", follow_redirects=False)
    assert len(chat.messages) == 0


@pytest.mark.anyio
async def test_clear_preserves_msg_counter(client):
    await client.post("/send", data={"msg": "before"})
    counter_before = chat.msg_counter
    await client.get(f"/clear?secret={chat.CLEAR_SECRET}", follow_redirects=False)
    assert chat.msg_counter == counter_before
    chat.last_sent.clear()
    await client.post("/send", data={"msg": "after"})
    assert chat.messages[0]["id"] == counter_before


# --- Body limit ---


@pytest.mark.anyio
async def test_body_limit_rejects_large_post(client):
    r = await client.post("/send", data={"msg": "A" * 3000}, follow_redirects=False)
    assert r.status_code == 413


@pytest.mark.anyio
async def test_body_limit_has_security_headers(client):
    r = await client.post("/send", data={"msg": "A" * 3000}, follow_redirects=False)
    assert r.headers["server"] == "onionchat"
    assert "default-src 'none'" in r.headers["content-security-policy"]


@pytest.mark.anyio
async def test_404_no_framework_leak(client):
    r = await client.get("/wp-login.php")
    assert r.status_code == 404
    assert "detail" not in r.text
    assert "Not Found" not in r.text


# --- Rate limit cleanup ---


def test_clean_rate_limits():
    chat.last_sent["old"] = time.monotonic() - 10
    chat.last_sent["new"] = time.monotonic()
    chat._clean_rate_limits()
    assert "old" not in chat.last_sent
    assert "new" in chat.last_sent


# --- Security headers ---


@pytest.mark.anyio
async def test_security_headers(client):
    r = await client.get("/")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-frame-options"] == "SAMEORIGIN"
    assert "camera=()" in r.headers["permissions-policy"]
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["server"] == "onionchat"


# --- Docs disabled ---


@pytest.mark.anyio
async def test_docs_disabled(client):
    for path in ["/docs", "/redoc", "/openapi.json"]:
        r = await client.get(path)
        assert r.status_code == 404


# --- Stream limit ---


@pytest.mark.anyio
async def test_stream_limit(client):
    chat.active_streams = chat.MAX_STREAMS
    r = await client.get("/messages")
    assert r.status_code == 200
    assert "Chat full" in r.text


@pytest.mark.anyio
async def test_stream_slot_reserved_immediately():
    """Verify active_streams is incremented before the generator starts,
    preventing race conditions under concurrent load."""
    from starlette.requests import Request

    scope = {"type": "http", "method": "GET", "path": "/messages",
             "query_string": b"", "headers": []}
    request = Request(scope)

    chat.active_streams = 0
    old_max = chat.MAX_STREAMS
    chat.MAX_STREAMS = 2
    try:
        # First call: slot reserved immediately, before generator runs
        r1 = await chat.msg_feed(request)
        assert isinstance(r1, StreamingResponse)
        assert chat.active_streams == 1

        # Second call: still room
        r2 = await chat.msg_feed(request)
        assert isinstance(r2, StreamingResponse)
        assert chat.active_streams == 2

        # Third call: full — no slot reserved
        r3 = await chat.msg_feed(request)
        assert isinstance(r3, HTMLResponse)
        assert chat.active_streams == 2  # unchanged
    finally:
        chat.MAX_STREAMS = old_max


# --- Notify ---


@pytest.mark.anyio
async def test_notify_wakes_waiters():
    event = chat.msg_event
    triggered = False

    async def waiter():
        nonlocal triggered
        await asyncio.wait_for(event.wait(), timeout=2)
        triggered = True

    task = asyncio.create_task(waiter())
    await asyncio.sleep(0.05)
    chat.notify()
    await task
    assert triggered


# --- Status ---


@pytest.mark.anyio
async def test_api_status_empty(client):
    r = await client.get("/api/status")
    assert r.status_code == 200
    data = r.json()
    assert data["streams"] == 0
    assert data["messages"] == 0
    assert data["limits"]["max_streams"] == chat.MAX_STREAMS
    assert data["limits"]["max_message_length"] == chat.MAX_MSG_LEN
    assert data["hardening"]["docs_disabled"] is True
    assert data["hardening"]["cookie_secure"] is False
    assert "note" in data


@pytest.mark.anyio
async def test_api_status_with_messages(client):
    await client.post("/send", data={"msg": "hi"})
    r = await client.get("/api/status")
    assert r.json()["messages"] == 1


@pytest.mark.anyio
async def test_api_messages_empty(client):
    r = await client.get("/api/messages")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.anyio
async def test_api_messages(client):
    await client.post("/send", data={"msg": "hello"})
    r = await client.get("/api/messages")
    data = r.json()
    assert len(data) == 1
    assert data[0]["text"] == "hello"
    assert "nick" in data[0]
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z", data[0]["time"])


@pytest.mark.anyio
async def test_api_messages_no_id_leak(client):
    await client.post("/send", data={"msg": "test"})
    r = await client.get("/api/messages")
    assert "id" not in r.json()[0]


@pytest.mark.anyio
async def test_render_msg_shows_only_hhmm():
    m = {"id": 0, "nick": "Fox-ab12", "time": "2026-03-30T15:23Z", "text": "hi"}
    html = chat.render_msg(m)
    assert "15:23" in html
    assert "2026" not in html
