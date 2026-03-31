# CLAUDE.md

## Project

Anonymous chat server for Tor Onion Services. Python implementation.
Sister project: [onionchat-go](https://github.com/lubeschanin/onionchat-go)

## Stack

- Python 3.12+, FastAPI, Jinja2, uvicorn, python-multipart
- Dependency management: uv
- No JavaScript, no WebSocket, no database

## Architecture

- HTTP streaming via `StreamingResponse` + `asyncio.Event` for real-time delivery
- Three iframes: chat (streaming), clock (meta-refresh 30s), form in main page
- Auto-scroll via `flex-direction: column-reverse` on scroll container
- CSS fade-in (1.2s) masks stream restart on send
- Raw ASGI middleware (not `BaseHTTPMiddleware`) to avoid buffering streams
- Subscribe-before-snapshot pattern to prevent missed messages

## Commands

```bash
./start.sh              # Start server
uv run chat.py          # Alternative start
uv run pytest           # Run 35 tests
uv run pytest -v        # Verbose
```

## Key decisions

- No `/clear` endpoint — restart to clear. Eliminates secret management.
- `active_streams` incremented before generator, decremented in `finally`
- Duplicate filter: per-nick, 30s window, survives interleaved messages
- Cleanup cutoff uses 30s (duplicate window), not 2s (rate limit)
- Cookie: httponly, samesite=strict, no Secure flag (plain HTTP, Tor encrypts)
- All timestamps stored ISO 8601, rendered HH:MM in UI

## Constraints

- No JavaScript — all interactivity via HTML forms, CSS, HTTP streaming
- Bind 127.0.0.1:8181 only — Tor forwards traffic
- Single process, in-memory state — ephemeral by design
