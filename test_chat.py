"""Tests for onionchat."""

import asyncio
import time

import pytest
from httpx import ASGITransport, AsyncClient

import chat


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset global state between tests."""
    chat.messages.clear()
    chat.msg_counter = 0
    chat.last_sent.clear()
    chat.active_streams = 0
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
    chat.last_sent.clear()
    await client.post("/send", data={"msg": long_msg})
    assert len(chat.messages[0]["text"]) == chat.MAX_MSG_LEN


# --- Ring buffer ---


def test_ring_buffer():
    for i in range(250):
        chat.messages.append({"id": i, "nick": "X-0000", "time": "00:00", "text": str(i)})
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
