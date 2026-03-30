# onionchat

[![tests](https://github.com/lubeschanin/onionchat/actions/workflows/test.yml/badge.svg)](https://github.com/lubeschanin/onionchat/actions/workflows/test.yml)

Minimal anonymous chat server for Tor Onion Services.

No JavaScript. No WebSocket. No database. No bloat. One Python file.

## Quickstart

```bash
git clone https://github.com/lubeschanin/onionchat.git
cd onionchat
./start.sh
```

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). Starts on `127.0.0.1:8181`.

## How it works

```
Browser                          Server (127.0.0.1:8181)
  |                                |
  |-- GET / ---------------------->|  Main page (form + chat iframe)
  |-- GET /messages -------------->|  Streaming HTML (open connection)
  |-- GET /clock ----------------->|  UTC clock (auto-refresh 30s)
  |                                |
  |-- POST /send ----------------->|  Append message, notify streams
  |<-- 303 -> / ------------------|  Page reloads (fade-in, autofocus)
  |                                |
  |   <-- new <div> chunks --------|  All streams get the new message
```

Messages are pushed via HTTP streaming (`StreamingResponse`). No polling, no refresh, no JavaScript. The browser renders HTML chunks as they arrive over the open connection.

## Features

- **Zero JavaScript** — pure HTML + CSS + HTTP streaming
- **Anonymous nicknames** — randomly generated on first visit (e.g. `Shadow-7a3b`), stored in cookie
- **Real-time delivery** — messages pushed via `asyncio.Event`, not polling
- **Ephemeral** — in-memory ring buffer (200 messages). Process dies, everything is gone. That's the point.
- **JSON API** — `GET /api/messages` and `GET /api/status` for programmatic access
- **Hardened** — CSP, rate limiting, body size limit, constant-time secret comparison ([full audit](AUDIT.md))

## Architecture

The UI uses iframes to work around HTML limitations without JS:

| Component | Endpoint | Purpose |
|---|---|---|
| Main page | `GET /` | Layout with form + chat iframe, reloads on send (fade-in transition) |
| Chat | `GET /messages` | Streaming response — stays open, receives new messages as HTML chunks |
| Clock | `GET /clock` | UTC date and time, auto-refreshes every 30s |

**Why an iframe for chat?** Without JS, there's no way to update part of a page. The chat iframe streams new messages via HTTP streaming. On send, the main page reloads with a CSS fade-in to mask the transition. Auto-scroll via `flex-direction: column-reverse` keeps newest messages visible.

**Why HTTP streaming over meta-refresh?** Meta-refresh reloads the entire page every N seconds, causing flicker and interrupting typing. HTTP streaming keeps the connection open and pushes new HTML chunks on demand — instant delivery, no flicker.

## Setup

### Run locally

```bash
./start.sh
```

Or manually:

```bash
uv run chat.py
```

On startup, the clear URL is printed to stdout:

```
[*] Clear-URL: /clear?secret=<random>
```

### Run as Tor Hidden Service

Add to your `torrc`:

```
HiddenServiceDir /var/lib/tor/onionchat/
HiddenServicePort 80 127.0.0.1:8181
```

Reload Tor, then find your `.onion` address:

```bash
sudo systemctl reload tor
cat /var/lib/tor/onionchat/hostname
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `CLEAR_SECRET` | random (printed on startup) | Secret for `/clear` endpoint |
| `MAX_STREAMS` | `100` | Max concurrent streaming connections |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Main page |
| `GET` | `/messages` | Streaming message feed (long-lived connection) |
| `GET` | `/clock` | Date and time (YYYY-MM-DD HH:MM UTC) |
| `POST` | `/send` | Send a message (form data: `msg`) |
| `GET` | `/api/messages` | JSON array of all messages (ISO 8601 timestamps) |
| `GET` | `/api/status` | JSON: streams, messages, limits, hardening config |
| `GET` | `/clear?secret=<s>` | Clear all messages (operator only) |

## Security

Full security self-audit: [`AUDIT.md`](AUDIT.md)

The `/api/status` endpoint exposes all limits and hardening settings transparently.

### Headers (all responses)

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'; form-action 'self'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Referrer-Policy` | `no-referrer` |
| `Cache-Control` | `no-store` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), interest-cohort=()` |
| `Server` | `onionchat` (uvicorn header suppressed) |

### Hardening

| Measure | Detail |
|---|---|
| XSS | `html.escape()` on all user content, CSP blocks all scripts |
| Body size | ASGI middleware rejects request bodies >2 KB (413) |
| Rate limiting | 1 msg/s per nickname |
| Message length | 500 chars max |
| Stream limit | 100 concurrent connections |
| Cookie validation | Regex-validated, invalid cookies replaced |
| Clear endpoint | Constant-time secret comparison |
| No fingerprint | Docs disabled, server header masked |
| No logging | `access_log=False`, no IP addresses stored |
| Middleware | Raw ASGI (not `BaseHTTPMiddleware`) to avoid buffering streams |

## Limits

| Resource | Limit |
|---|---|
| Messages in memory | 200 (ring buffer) |
| Message length | 500 chars |
| Request body | 2 KB |
| Concurrent streams | 100 |
| Rate limit | 1 msg/s per nick |

## Tests

```bash
uv run pytest
```

34 tests covering XSS, rate limiting, cookie validation, security headers, stream limits, body limits, API endpoints, and more.

## Project structure

```
onionchat/
├── chat.py              # Server (346 lines)
├── test_chat.py         # Tests (34 tests)
├── templates/
│   └── chat.html        # Outer layout (iframe shell)
├── pyproject.toml
├── start.sh
├── AUDIT.md             # Security audit
└── README.md
```

## What this doesn't have

No JavaScript. No WebSocket. No database. No accounts. No rooms. No DMs. No file uploads. No CDN. No external requests. No CORS. No TLS (Tor handles encryption). No IP logging. No frameworks beyond FastAPI.

## License

MIT
