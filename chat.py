"""Anonymous chat server for Tor Onion Services. No JS, no bloat."""

import asyncio
import os
import re
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from html import escape

from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory="templates")

messages: deque[dict] = deque(maxlen=200)
msg_counter: int = 0
msg_event = asyncio.Event()
active_streams: int = 0
MAX_STREAMS: int = int(os.environ.get("MAX_STREAMS", "100"))
MAX_MSG_LEN: int = 500
RATE_LIMIT: float = 1.0  # seconds between messages
last_sent: dict[str, float] = {}

NICK_RE = re.compile(r"^[A-Za-z]{2,10}-[0-9a-f]{4}$")

MAX_BODY: int = 2048


class BodyLimitMiddleware:
    """Reject request bodies larger than MAX_BODY bytes."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        received = 0
        too_large = False
        sent_413 = False

        async def limited_receive():
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > MAX_BODY:
                    too_large = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def checked_send(message):
            nonlocal sent_413
            if too_large and not sent_413:
                sent_413 = True
                await send({"type": "http.response.start", "status": 413, "headers": []})
                await send({"type": "http.response.body", "body": b"", "more_body": False})
                return
            if sent_413:
                return
            await send(message)

        await self.app(scope, limited_receive, checked_send)


SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"SAMEORIGIN"),
    (b"cache-control", b"no-store"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    (b"content-security-policy",
     b"default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'; form-action 'self'"),
    (b"server", b"onionchat"),
]


class SecurityHeadersMiddleware:
    """Raw ASGI middleware — does not buffer streaming responses."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(SECURITY_HEADERS)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(BodyLimitMiddleware)

CLEAR_SECRET = os.environ.get("CLEAR_SECRET", secrets.token_hex(8))

WORDS = [
    "Ash", "Bark", "Bear", "Blade", "Blaze", "Bolt", "Bone", "Briar",
    "Brook", "Cairn", "Cave", "Cinder", "Claw", "Clay", "Cliff", "Cloud",
    "Coal", "Cobra", "Coral", "Crane", "Creek", "Crow", "Dagger", "Dawn",
    "Deer", "Drift", "Dune", "Dusk", "Eagle", "Echo", "Ember", "Falcon",
    "Fang", "Fern", "Flare", "Flame", "Flint", "Fog", "Forge", "Fox",
    "Frost", "Gale", "Ghost", "Glacier", "Glyph", "Granite", "Grove", "Hail",
    "Hawk", "Haze", "Hollow", "Hornet", "Iron", "Ivy", "Jackal", "Jade",
    "Lark", "Lava", "Lichen", "Lynx", "Marsh", "Mist", "Moon", "Moss",
    "Moth", "Night", "Oak", "Obsidian", "Onyx", "Orca", "Osprey", "Owl",
    "Peak", "Pebble", "Pine", "Plume", "Quartz", "Raven", "Reed", "Ridge",
    "Root", "Ruin", "Rust", "Sage", "Shard", "Slate", "Smoke", "Snake",
    "Spark", "Star", "Stone", "Storm", "Thorn", "Thunder", "Tide", "Viper",
    "Wave", "Willow", "Wolf", "Wren",
]


def make_nick() -> str:
    return f"{secrets.choice(WORDS)}-{secrets.token_hex(2)}"


def get_or_set_nick(request: Request, response: Response) -> str:
    nick = request.cookies.get("nick")
    if not nick or not NICK_RE.match(nick):
        nick = make_nick()
        # No Secure flag: server binds 127.0.0.1 (plain HTTP), Tor encrypts the transport.
        response.set_cookie("nick", nick, httponly=True, samesite="strict")
    return nick


def notify():
    global msg_event
    old = msg_event
    msg_event = asyncio.Event()
    old.set()


def render_msg(m: dict) -> str:
    hhmm = escape(m["time"][11:16])
    return (
        f'<div class="msg">'
        f'<span class="ts">{hhmm}</span> '
        f'<span class="nick">{escape(m["nick"])}</span> '
        f'<span class="text">{escape(m["text"])}</span>'
        f'</div>\n'
    )


def _clean_rate_limits():
    """Remove entries older than 2x RATE_LIMIT."""
    cutoff = time.monotonic() - RATE_LIMIT * 2
    expired = [k for k, v in last_sent.items() if v < cutoff]
    for k in expired:
        del last_sent[k]


MSG_HEAD = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><style>'
    '*{margin:0;padding:0;box-sizing:border-box}'
    'body{background:#0d0d0d;color:#c0c0c0;font-family:monospace;font-size:14px;padding:12px;'
    'scrollbar-color:#222 #0d0d0d;scrollbar-width:thin}'
    '.msg{margin-bottom:4px;word-wrap:break-word}'
    '.msg .ts{color:#666}.msg .nick{color:#888;font-weight:bold}.msg .text{color:#00cc66}'
    '</style></head><body>\n'
)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    response = templates.TemplateResponse(request, "chat.html")
    get_or_set_nick(request, response)
    return response


@app.get("/clock", response_class=HTMLResponse)
async def clock():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return HTMLResponse(
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<meta http-equiv="refresh" content="30">'
        '<style>*{margin:0;padding:0}body{background:transparent;'
        'font-family:monospace;font-size:10px;color:#333}</style>'
        f'</head><body>{now}</body></html>'
    )


FULL_HTML = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<meta http-equiv="refresh" content="10;url=/messages"><style>'
    '*{margin:0;padding:0;box-sizing:border-box}'
    'body{background:#0d0d0d;color:#666;font-family:monospace;font-size:14px;'
    'display:flex;justify-content:center;align-items:center;height:100vh}'
    '</style></head><body>Chat full — retrying...</body></html>'
)


@app.get("/messages")
async def msg_feed(request: Request):
    global active_streams
    if active_streams >= MAX_STREAMS:
        return HTMLResponse(FULL_HTML)

    async def generate():
        global active_streams
        active_streams += 1
        try:
            yield MSG_HEAD

            last_id = -1
            for m in list(messages):
                yield render_msg(m)
                last_id = m["id"]

            while True:
                event = msg_event
                try:
                    await asyncio.wait_for(event.wait(), timeout=30)
                except asyncio.TimeoutError:
                    yield '<!-- ping -->\n'
                    if await request.is_disconnected():
                        break
                    continue
                if await request.is_disconnected():
                    break
                for m in list(messages):
                    if m["id"] > last_id:
                        yield render_msg(m)
                        last_id = m["id"]
        finally:
            active_streams -= 1

    return StreamingResponse(generate(), media_type="text/html")


INPUT_HTML = (
    '<!DOCTYPE html><html><head><meta charset="utf-8"><style>'
    '*{margin:0;padding:0;box-sizing:border-box}'
    'body{background:#111}'
    'form{display:flex;gap:8px;padding:8px 12px}'
    'input[type=text]{flex:1;background:#0d0d0d;color:#00cc66;border:1px solid #333;'
    'padding:8px;font-family:monospace;font-size:14px;outline:none}'
    'input[type=text]:focus{border-color:#00cc66}'
    'button{background:#00cc66;color:#0d0d0d;border:none;padding:8px 16px;'
    'font-family:monospace;font-size:14px;font-weight:bold;cursor:pointer}'
    'button:hover{background:#00ff7f}'
    '</style></head><body>'
    '<form action="/send" method="post" autocomplete="off">'
    f'<input type="text" name="msg" placeholder="Message..." maxlength="{MAX_MSG_LEN}" autofocus>'
    '<button type="submit">&gt;</button>'
    '</form></body></html>'
)


@app.get("/input", response_class=HTMLResponse)
async def input_form(request: Request):
    response = HTMLResponse(INPUT_HTML)
    get_or_set_nick(request, response)
    return response


@app.post("/send")
async def send(request: Request, msg: str = Form("")):
    global msg_counter
    response = RedirectResponse("/input", status_code=303)
    nick = get_or_set_nick(request, response)
    text = msg.strip()[:MAX_MSG_LEN]
    now = time.monotonic()
    if text and now - last_sent.get(nick, 0) >= RATE_LIMIT:
        last_sent[nick] = now
        messages.append({
            "id": msg_counter,
            "nick": nick,
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ"),
            "text": text,
        })
        msg_counter += 1
        notify()
        if len(last_sent) > 256:
            _clean_rate_limits()
    return response


@app.get("/api/messages")
async def api_messages():
    return [{"nick": m["nick"], "time": m["time"], "text": m["text"]} for m in messages]


@app.get("/api/status")
async def api_status():
    return {"streams": active_streams, "messages": len(messages)}


@app.get("/clear")
async def clear(secret: str = ""):
    if secrets.compare_digest(secret, CLEAR_SECRET):
        # msg_counter is intentionally NOT reset — streaming generators track
        # last_id, so a reset would cause them to miss new messages.
        messages.clear()
    return RedirectResponse("/", status_code=303)


if __name__ == "__main__":
    import uvicorn
    print(f"[*] Clear-URL: /clear?secret={CLEAR_SECRET}")
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8181,
        access_log=False,
        server_header=False,
        h11_max_incomplete_event_size=16 * 1024,
    )
