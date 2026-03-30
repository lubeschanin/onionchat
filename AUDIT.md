# Security Self-Audit — onionchat

**Date:** 2026-03-30
**Type:** Self-audit (not an independent security review)
**Scope:** `chat.py` (352 lines), `templates/chat.html` (23 lines), `test_chat.py` (377 lines)
**Threat model:** Anonymous chat over Tor. Adversaries: malicious chat participants, network observers, automated scanners.

### Confidence levels

- **TESTED** — behavior verified by automated test
- **INSPECTED** — verified by code review only, no automated test
- **MITIGATED** — risk reduced but not eliminated

### Known limitations

- Single-process, single-worker. All state is global in-memory. Not designed for multi-worker or horizontal scaling.
- This is a self-audit, not a pentest. Claims below reflect what the code does, not formal proof of absence of vulnerabilities.
- Tests cover behavior at the application level. Infrastructure-level concerns (Tor configuration, OS hardening, uvicorn internals) are out of scope.

---

## 1. Input Validation

| Vector | Status | Detail |
|---|---|---|
| Message text (XSS) | **TESTED** | `html.escape()` on nick, time, text in `render_msg()`. Jinja2 auto-escaping on `chat.html`. No `\|safe` filters. |
| Message length | **TESTED** | Server truncates at 500 chars (`msg.strip()[:MAX_MSG_LEN]`). HTML `maxlength="500"` on input. |
| Cookie nickname | **TESTED** | Validated against `^[A-Za-z]{2,10}-[0-9a-f]{4}$`. Invalid cookies replaced with server-generated nick. |
| Form data body | **TESTED** | `BodyLimitMiddleware` rejects bodies >2 KB at ASGI level. Returns 413 with security headers. |
| HTTP headers | **INSPECTED** | `h11_max_incomplete_event_size=16KB` limits header size at protocol level. Not tested — depends on uvicorn/h11 internals. |
| Query parameters | **INSPECTED** | `/clear` secret compared with `secrets.compare_digest()`. Code uses constant-time comparison, but no timing test proves it. |

### Tests

- `test_xss_escaped` — `<script>` tags are entity-encoded
- `test_message_truncated` — 1000-char message truncated to 500
- `test_invalid_cookie_gets_new_nick` — XSS payload in cookie replaced
- `test_too_long_cookie_gets_new_nick` — oversized cookie replaced
- `test_body_limit_rejects_large_post` — 3 KB body returns 413
- `test_body_limit_has_security_headers` — 413 response includes CSP and server header

---

## 2. HTTP Response Headers

| Header | Value | Purpose |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'; form-action 'self'` | Blocks scripts, images, external resources |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `SAMEORIGIN` | Prevents clickjacking from external sites |
| `Referrer-Policy` | `no-referrer` | No `.onion` address leakage via referrer |
| `Cache-Control` | `no-store` | Prevents caching of messages |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), interest-cohort=()` | Disables browser APIs and FLoC |
| `Server` | `onionchat` | Hides uvicorn fingerprint (`server_header=False`) |

### Implementation

Raw ASGI middleware (`SecurityHeadersMiddleware`), not `BaseHTTPMiddleware`. This is important because `BaseHTTPMiddleware` buffers entire response bodies, which would break the streaming `/messages` endpoint.

### Tests

- `test_security_headers` — verifies all headers present with correct values on normal responses
- `test_body_limit_has_security_headers` — verifies headers present on 413 error responses

### Not tested

- Whether headers are present on all possible error paths (e.g. uvicorn-level errors before middleware runs)

---

## 3. Denial of Service

| Vector | Mitigation | Limit |
|---|---|---|
| Stream exhaustion | `active_streams` counter with immediate reservation | 100 (configurable via `MAX_STREAMS`) |
| Message spam | Per-nick rate limit via `last_sent` dict | 1 msg/s per nick |
| Large POST body | `BodyLimitMiddleware` at ASGI level | 2 KB |
| Large HTTP headers | `h11_max_incomplete_event_size` | 16 KB |
| Memory via messages | `deque(maxlen=200)` ring buffer | 200 messages max |
| Memory via rate-limit dict | `_clean_rate_limits()` called when >256 entries | Entries >2s old evicted |

### `/api/messages` — no rate limit (intentional)

Read-only, bounded payload (~20 KB max). Tor latency (200-1000ms) is the natural throttle. Adding rate limiting would be complexity without practical benefit for this threat model.

### Stream counter

- `active_streams += 1` is called immediately in `msg_feed()`, before the generator is created — prevents race condition where concurrent requests pass the check before generators start
- `active_streams -= 1` in the generator's `finally` block
- ASGI guarantees the generator is started (via `StreamingResponse.__call__`) and `aclose()`d on disconnect, so `finally` always runs in practice
- Theoretical slot leak if the generator is never started (requires ASGI server bug) — accepted risk

### Tests

- `test_stream_limit` — "Chat full" response at max capacity
- `test_stream_slot_reserved_immediately` — counter increments before generator runs, rejection at capacity works
- `test_rate_limit` — second message within 1s is dropped
- `test_rate_limit_expires` — message accepted after limit expires
- `test_ring_buffer` — deque evicts oldest at 200
- `test_clean_rate_limits` — expired entries removed, recent entries kept

### Not tested

- Behavior under actual concurrent load (multiple simultaneous HTTP connections). Tests verify the reservation logic in isolation, not under real network concurrency.
- Header size limit — depends on h11 internals.

---

## 4. Information Leakage

| Vector | Status | Detail |
|---|---|---|
| IP logging | **INSPECTED** | `access_log=False` in uvicorn config. Not verified that no other code path logs IPs. |
| Server fingerprint | **TESTED** | `server_header=False` + custom `Server: onionchat` |
| OpenAPI/docs | **TESTED** | `docs_url=None, redoc_url=None, openapi_url=None` |
| Error pages | **TESTED** | Custom exception handler returns empty body. No FastAPI JSON fingerprint. |
| Referrer leakage | **INSPECTED** | `Referrer-Policy: no-referrer` header set. Browser compliance assumed, not verified. |
| Timezone leakage | **INSPECTED** | All timestamps UTC. Stored as ISO 8601. UI shows only `HH:MM`. |
| Cache leakage | **INSPECTED** | `Cache-Control: no-store` on all responses. Browser/proxy compliance assumed. |
| External requests | **INSPECTED** | No CDN, no fonts, no analytics. CSP `default-src 'none'` enforces this in supporting browsers. |
| Internal ID leakage | **TESTED** | `/api/messages` strips internal `id` field. |

### Tests

- `test_docs_disabled` — `/docs`, `/redoc`, `/openapi.json` return 404
- `test_security_headers` — server header is `onionchat`
- `test_api_messages_no_id_leak` — internal `id` not in JSON API
- `test_404_no_framework_leak` — unknown paths return empty body, no `{"detail":"Not Found"}`

---

## 5. Authentication & Authorization

| Concern | Status | Detail |
|---|---|---|
| Nickname spoofing | **MITIGATED** | Cookie is `httponly` + `samesite=strict`. Server validates format. No `Secure` flag — server binds `127.0.0.1` (plain HTTP), Tor encrypts the transport. |
| Clear endpoint | **INSPECTED** | Protected by `CLEAR_SECRET` with `secrets.compare_digest()`. Code uses constant-time comparison, but no timing test verifies it. 64 bits of entropy via `secrets.token_hex(8)`. |
| Session fixation | **N/A** | No sessions. Cookie is a display name only, not an auth token. |

### Tests

- `test_clear_wrong_secret` — wrong secret does not clear
- `test_clear_correct_secret` — correct secret clears
- `test_send_preserves_existing_nick` — valid cookie kept
- `test_invalid_cookie_gets_new_nick` — invalid cookie replaced

---

## 6. Concurrency & State

| Concern | Status | Detail |
|---|---|---|
| Global state safety | **INSPECTED** | All state accessed within single asyncio event loop. No threads. Correct for single-worker deployment only. |
| Event notification | **INSPECTED** | `notify()` replaces `msg_event` and sets old. Generators capture reference before `await`. Appears correct by inspection. |
| Deque iteration | **INSPECTED** | `list(messages)` snapshots before iterating. Safe against concurrent modification in asyncio context. |
| `msg_counter` overflow | **INSPECTED** | Python `int` has arbitrary precision. |
| `/clear` + streaming | **TESTED** | `msg_counter` not reset on clear. New messages get higher IDs. |
| Stream slot reservation | **TESTED** | Slot reserved before generator creation. Counter correct at capacity. |

### Tests

- `test_notify_wakes_waiters` — event notification works
- `test_clear_preserves_msg_counter` — counter survives clear, new messages get correct IDs
- `test_stream_slot_reserved_immediately` — immediate reservation, correct rejection

### Not tested

- Multi-worker behavior. All global state would break with multiple processes. This is a single-process tool by design.

---

## 7. JSON API

| Endpoint | Method | Auth | Response |
|---|---|---|---|
| `/api/messages` | `GET` | None | `[{"nick", "time" (ISO 8601), "text"}, ...]` |
| `/api/status` | `GET` | None | `{"streams", "messages", "limits", "hardening"}` |

Both endpoints are public and read-only. No internal state (`id`, `msg_counter`) is exposed. The status endpoint transparently exposes all configured limits and hardening settings, including what is **not** enabled (e.g. `cookie_secure: false`).

### Tests

- `test_api_status_empty` — zeroed status on fresh start
- `test_api_status_with_messages` — message counter after send
- `test_api_messages_empty` — empty array
- `test_api_messages` — message fields present, ISO 8601 timestamp format
- `test_api_messages_no_id_leak` — internal `id` not exposed

---

## 8. Remaining Risks (accepted)

| Risk | Severity | Rationale |
|---|---|---|
| Nickname collision | **Low** | 100 words x 65536 suffixes = ~6.5M combinations. Cosmetic, not security-critical. |
| Rate limit bypass via cookie deletion | **Low** | New nick bypasses rate limit. Tor circuit creation is slower than 1 msg/s. |
| No CSRF token on `/send` | **Low** | `SameSite=Strict` + CSP `form-action 'self'` as defense in depth. |
| Stream slot leak | **Low** | Possible if generator never starts (requires ASGI server bug). ASGI spec guarantees response execution. |
| `last_sent` cleanup timing | **Low** | Dict can hold up to 256 stale entries (~10 KB). Bounded and harmless. |
| API polling | **Low** | No rate limit on read-only API. Tor latency is the natural throttle. |
| Single-process state | **Accepted** | All state is in-memory, global. Not designed for multi-worker. Process restart clears everything. This is intentional. |

---

## 9. Dependency Surface

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

## 10. Test Summary

```
34 tests, 0.24s

Nickname:       test_make_nick_format, test_make_nick_unique
Pages:          test_index, test_input, test_clock
Send/receive:   test_send_message, test_send_empty_ignored,
                test_send_sets_nick_cookie, test_send_preserves_existing_nick
XSS:            test_xss_escaped
Limits:         test_message_truncated, test_ring_buffer
Rate limiting:  test_rate_limit, test_rate_limit_expires, test_clean_rate_limits
Cookie:         test_invalid_cookie_gets_new_nick, test_too_long_cookie_gets_new_nick
Clear:          test_clear_wrong_secret, test_clear_correct_secret,
                test_clear_preserves_msg_counter
Body limit:     test_body_limit_rejects_large_post, test_body_limit_has_security_headers
Fingerprint:    test_404_no_framework_leak
Headers:        test_security_headers
Docs:           test_docs_disabled
Streams:        test_stream_limit, test_stream_slot_reserved_immediately
Events:         test_notify_wakes_waiters
Timestamps:     test_render_msg_shows_only_hhmm
API:            test_api_status_empty, test_api_status_with_messages,
                test_api_messages_empty, test_api_messages,
                test_api_messages_no_id_leak
```

---

## 11. Verdict

This is a self-audit of a small, intentionally minimal project. The codebase is clean, the scope is narrow, and the hardening measures are appropriate for the threat model.

No critical issues were found. The code does what it claims, with reasonable input validation, header hardening, and resource limits. The tests cover the core security-relevant behavior.

What this audit does **not** claim:
- Formal verification of absence of vulnerabilities
- Coverage of infrastructure-level concerns (Tor config, OS, network)
- Applicability beyond single-process, single-worker deployment
- Resistance to a determined attacker with local access to the server

The accepted risks are documented above. For what it is — an anonymous, ephemeral, single-process chat over Tor — the code is solid.
