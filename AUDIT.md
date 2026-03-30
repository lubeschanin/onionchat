# Security Audit — onionchat

**Date:** 2026-03-29
**Scope:** `chat.py` (304 lines), `templates/chat.html` (23 lines), `test_chat.py` (257 lines)
**Threat model:** Anonymous chat over Tor. Adversaries: malicious chat participants, network observers, automated scanners.

---

## 1. Input Validation

| Vector | Status | Detail |
|---|---|---|
| Message text (XSS) | **PASS** | `html.escape()` on nick, time, text in `render_msg()`. Jinja2 auto-escaping on `chat.html`. No `|safe` filters. |
| Message length | **PASS** | Server truncates at 500 chars (`msg.strip()[:MAX_MSG_LEN]`). HTML `maxlength="500"` on input. |
| Cookie nickname | **PASS** | Validated against `^[A-Za-z]{2,10}-[0-9a-f]{4}$`. Invalid cookies replaced with server-generated nick. |
| Form data body | **PASS** | `BodyLimitMiddleware` rejects bodies >2 KB at ASGI level before parsing. Returns 413. |
| HTTP headers | **PASS** | `h11_max_incomplete_event_size=16KB` limits header size at protocol level. |
| Query parameters | **PASS** | `/clear` secret compared with `secrets.compare_digest()` (constant-time). |

### Test coverage

- `test_xss_escaped` — verifies `<script>` tags are entity-encoded
- `test_message_truncated` — verifies 1000-char message truncated to 500
- `test_invalid_cookie_gets_new_nick` — verifies XSS in cookie replaced
- `test_too_long_cookie_gets_new_nick` — verifies oversized cookie replaced

---

## 2. HTTP Response Headers

| Header | Value | Purpose |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'; form-action 'self'` | Blocks scripts, images, external resources. Only inline CSS and same-origin iframes/forms allowed. |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `SAMEORIGIN` | Prevents clickjacking from external sites |
| `Referrer-Policy` | `no-referrer` | No `.onion` address leakage via referrer |
| `Cache-Control` | `no-store` | Prevents caching of messages by browser/proxies |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), interest-cohort=()` | Disables browser APIs and FLoC |
| `Server` | `onionchat` | Hides uvicorn fingerprint (`server_header=False`) |

### Implementation

- Raw ASGI middleware (`SecurityHeadersMiddleware`), not `BaseHTTPMiddleware`
- **Critical distinction:** `BaseHTTPMiddleware` buffers entire response bodies, which would break the streaming `/messages` endpoint. The raw ASGI approach injects headers into `http.response.start` without buffering.

### Test coverage

- `test_security_headers` — verifies all headers present with correct values

---

## 3. Denial of Service

| Vector | Mitigation | Limit |
|---|---|---|
| Stream exhaustion | `active_streams` counter, checked before creating generator | 100 (configurable via `MAX_STREAMS`) |
| Message spam | Per-nick rate limit via `last_sent` dict | 1 msg/s per nick |
| Large POST body | `BodyLimitMiddleware` at ASGI level | 2 KB |
| Large HTTP headers | `h11_max_incomplete_event_size` | 16 KB |
| Memory via messages | `deque(maxlen=200)` ring buffer | 200 messages max |
| Memory via rate-limit dict | `_clean_rate_limits()` called when >256 entries | Entries >2s old evicted |

### Stream counter correctness

- `active_streams += 1` inside generator's `try` block (line 190)
- `active_streams -= 1` in `finally` block (line 215)
- Single-threaded asyncio — no race conditions
- Generator cleanup guaranteed by ASGI server on client disconnect

### Test coverage

- `test_stream_limit` — verifies "Chat full" response at max capacity
- `test_rate_limit` — verifies second message within 1s is dropped
- `test_rate_limit_expires` — verifies message accepted after limit expires
- `test_ring_buffer` — verifies deque evicts oldest at 200

---

## 4. Information Leakage

| Vector | Status | Detail |
|---|---|---|
| IP logging | **PASS** | `access_log=False` in uvicorn config |
| Server fingerprint | **PASS** | `server_header=False` + custom `Server: onionchat` |
| OpenAPI/docs | **PASS** | `docs_url=None, redoc_url=None, openapi_url=None` |
| Referrer leakage | **PASS** | `Referrer-Policy: no-referrer` |
| Timezone leakage | **PASS** | All timestamps UTC (`datetime.now(timezone.utc)`) |
| Error pages | **PASS** | FastAPI default error handler, no stack traces in production |
| Cache leakage | **PASS** | `Cache-Control: no-store` on all responses |
| External requests | **PASS** | No CDN, no fonts, no analytics, no external resources. CSP `default-src 'none'` enforces this. |

### Test coverage

- `test_docs_disabled` — verifies `/docs`, `/redoc`, `/openapi.json` return 404
- `test_security_headers` — verifies server header is `onionchat`

---

## 5. Authentication & Authorization

| Concern | Status | Detail |
|---|---|---|
| Nickname spoofing | **MITIGATED** | Cookie is `httponly` + `samesite=strict`. Cannot be read or set by other origins. Server validates format. |
| Clear endpoint | **PASS** | Protected by `CLEAR_SECRET` with constant-time comparison. Secret generated via `secrets.token_hex(8)` (64 bits of entropy). |
| Session fixation | **N/A** | No sessions. Cookie is a display name only, not an auth token. |

### Test coverage

- `test_clear_wrong_secret` — verifies wrong secret does not clear
- `test_clear_correct_secret` — verifies correct secret clears
- `test_send_preserves_existing_nick` — verifies valid cookie is kept
- `test_invalid_cookie_gets_new_nick` — verifies invalid cookie replaced

---

## 6. Concurrency & State

| Concern | Status | Detail |
|---|---|---|
| Global state safety | **PASS** | All state (`messages`, `msg_counter`, `msg_event`, `active_streams`, `last_sent`) accessed within single asyncio event loop. No threads. |
| Event notification | **PASS** | `notify()` replaces `msg_event` and sets old. Generators capture event reference before `await`. No missed notifications. |
| Deque iteration | **PASS** | `list(messages)` snapshots before iterating. Safe against concurrent modification. |
| `msg_counter` overflow | **PASS** | Python `int` has arbitrary precision. No overflow possible. |
| `/clear` + streaming | **PASS** | After `messages.clear()`, `msg_counter` is not reset. New messages get higher IDs. Existing streams continue correctly. |

### Test coverage

- `test_notify_wakes_waiters` — verifies event-based notification works

---

## 7. Remaining Risks (accepted)

| Risk | Severity | Rationale |
|---|---|---|
| Nickname collision | **Low** | 100 words x 65536 suffixes = ~6.5M combinations. Collision unlikely at 100 users. Not security-critical — nicknames are cosmetic. |
| Rate limit bypass via cookie deletion | **Low** | User can clear cookie, get new nick, bypass rate limit. Acceptable — Tor circuit creation is slower than 1 msg/s anyway. |
| No CSRF protection on `/send` | **Low** | `SameSite=Strict` cookie prevents cross-origin form submission. CSP `form-action 'self'` adds defense in depth. |
| Streaming connection drop | **Low** | If the stream drops silently (no `is_disconnected` trigger), the generator leaks until the next ping timeout (30s). `finally` block then cleans up. |
| `last_sent` cleanup timing | **Low** | Cleanup only fires at >256 entries. In theory, 256 nicks sending exactly 1 msg each would persist until threshold. Bounded and harmless. |

---

## 8. Dependency Surface

| Package | Purpose | Risk |
|---|---|---|
| `fastapi` | HTTP framework | Well-maintained, large community |
| `starlette` | ASGI toolkit (fastapi dependency) | Same |
| `jinja2` | Template rendering (chat.html only) | Auto-escaping enabled by default |
| `python-multipart` | Form data parsing | Required for `Form()` |
| `uvicorn` | ASGI server | Production-grade |
| `h11` | HTTP/1.1 parser (uvicorn dependency) | Minimal, well-tested |

No external runtime requests. No CDN. No telemetry. Attack surface limited to inbound HTTP on `127.0.0.1:8181`.

---

## 9. Test Summary

```
24 tests, 0.25s

Nickname:       test_make_nick_format, test_make_nick_unique
Pages:          test_index, test_input, test_clock
Send/receive:   test_send_message, test_send_empty_ignored,
                test_send_sets_nick_cookie, test_send_preserves_existing_nick
XSS:            test_xss_escaped
Limits:         test_message_truncated, test_ring_buffer
Rate limiting:  test_rate_limit, test_rate_limit_expires
Cookie:         test_invalid_cookie_gets_new_nick, test_too_long_cookie_gets_new_nick
Clear:          test_clear_wrong_secret, test_clear_correct_secret
Headers:        test_security_headers
Docs:           test_docs_disabled
Streams:        test_stream_limit
Status:         test_status_empty, test_status_with_messages
Events:         test_notify_wakes_waiters
```

---

## 10. Verdict

The codebase is minimal, hardened, and fit for purpose. No critical or high-severity issues found. The accepted low-severity risks are reasonable tradeoffs for the threat model (anonymous Tor chat, no persistent state, no authentication).
