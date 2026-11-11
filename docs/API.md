# NetControl REST API

Base URL:

```
http://127.0.0.1:8787/api/v1
https://<host>:8787/api/v1
```

The machine-readable contract is [`openapi.json`](openapi.json), also served at
`GET /api/v1/openapi.json`. `GET /health` is unauthenticated.

## Authentication

```bash
curl -s -X POST http://127.0.0.1:8787/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}'
```

Response:

```json
{
  "token": "opaque-32-byte-token",
  "expires_at": "2026-11-11T22:00:00Z",
  "user": {"id":"...","username":"admin","role":"admin", "...": "..."}
}
```

Send the token as `Authorization: Bearer <token>` or `X-API-Token: <token>`.
Tokens are stored server-side only as SHA-256 digests.

```bash
TOKEN=...
AUTH="Authorization: Bearer $TOKEN"
```

Roles: `admin` may mutate; `viewer` may read. Mutations are audited.

## Error model

```json
{"error":{"code":"validation_error","message":"..."}}
```

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | `validation_error` | invalid input or missing confirmation |
| 401 | `unauthorized` / `invalid_credentials` | login required / bad credentials |
| 403 | `forbidden` | role, scope guard, or confirmation required |
| 404 | `not_found` | unknown device/gateway |
| 409/422 | `conflict` / `unsupported` | scan in progress / operation not supported |
| 429 | `rate_limited` | login throttling |
| 502 | `gateway_error` | gateway transport/protocol failure |
| 500 | `internal_error` | generic internal failure |

## Endpoints

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/health` | public liveness |
| POST | `/auth/login` | issue session |
| POST | `/auth/logout` | revoke current session |
| GET | `/auth/me` | current user |
| POST | `/auth/password` | change own password; revokes sessions |
| GET | `/system/status` | version, platform, DB, TLS, privilege |
| GET | `/dashboard` | network, counts, gateway probe, traffic, last scan |
| GET | `/interfaces` | interface inventory |
| GET | `/networks` | known networks |
| POST | `/scans` | run an authorized scan |
| GET | `/scans` | recent scan sessions |
| GET | `/devices` | search/filter/page devices |
| GET | `/devices/{id}` | device + history + rules + traffic |
| PATCH | `/devices/{id}` | name/category/notes/trust |
| POST | `/devices/{id}/trust` | `{"trusted": true}` |
| POST | `/devices/{id}/block` | confirmation required; verified gateway |
| POST | `/devices/{id}/pause` | temp block with duration |
| POST | `/devices/{id}/unblock` | confirmation required |
| POST | `/devices/{id}/bandwidth` | download/upload/priority |
| DELETE | `/devices/{id}/bandwidth` | clear limits |
| GET | `/access-rules` | access rule history |
| GET | `/bandwidth-rules` | bandwidth rule history |
| GET | `/monitoring/overview` | current measured traffic |
| GET | `/monitoring/history` | minute-bucketed samples |
| GET | `/events?token=` | SSE stream |
| GET | `/audit` | admin audit log |
| GET/POST | `/gateways` | list/add gateways |
| PUT/DELETE | `/gateways/{id}` | update/delete |
| POST | `/gateways/{id}/test` | probe real capabilities |
| POST | `/gateways/{id}/activate` | select active gateway |
| GET | `/gateways/{id}/clients` | gateway client list |
| GET | `/gateway/status` | probe active gateway |
| GET/PUT | `/settings` | typed application settings |
| GET/POST | `/users` | admin user management |

## Examples

### Scan

```bash
curl -s -X POST "$BASE/scans" -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "interface": "enp1s0f1",
  "methods": ["neighbor","icmp","mdns"],
  "nmap": false,
  "ports": false,
  "confirm": true
}'
```

`confirm=false` is rejected. Public address space is rejected unless
`allow_public` is true **and** the server configuration permits it.

### Devices

```bash
curl -s "$BASE/devices?online=true&limit=50&sort=last_seen&order=desc" -H "$AUTH"
```

`sort` accepts `name`, `ip`, `last_seen`, `first_seen`, `category`, `vendor`,
`status`; values are mapped to a whitelist, never interpolated as SQL.

### Block (verified enforcement)

```bash
curl -s -X POST "$BASE/devices/<id>/block" -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"confirm":true,"duration_seconds":3600,"reason":"guest device"}'
```

```json
{
  "result": {
    "success": true,
    "verified": true,
    "action": "block",
    "target": "192.168.1.50",
    "adapter": "linux",
    "detail": "blocked 192.168.1.50 in nftables set netcontrol/blocked",
    "applied_at": "2026-11-11T12:00:00Z"
  },
  "device": {"is_blocked": true, "enforcement": "applied", "...": "..."}
}
```

If no gateway is configured, `success=false`, `verified=false`,
`action="unsupported"`, and the device is **not** modified.

### Bandwidth

```bash
curl -s -X POST "$BASE/devices/<id>/bandwidth" -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"confirm":true,"download_kbps":10000,"upload_kbps":2000,"priority":3}'
```

Rates are Kbps. `null` means no limit for that direction. Priority is 0-7 where
supported. Clear with `DELETE` and `{"confirm":true}`.

### Gateway

```bash
curl -s -X POST "$BASE/gateways" -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "name":"Local gateway",
  "kind":"linux",
  "host":"local",
  "interface_hint":"enp1s0f1"
}'
curl -s -X POST "$BASE/gateways/<id>/test" -H "$AUTH"
```

Secrets are accepted once and sealed with AES-256-GCM; they are never returned.

### SSE

```
GET /api/v1/events?token=<session-token>
```

Events are JSON frames named `netcontrol` with `type` one of
`scan_started`, `scan_completed`, `device_discovered`, `device_updated`,
`monitoring`, `enforcement`, `notification`.

### Audit

```bash
curl -s "$BASE/audit?limit=100" -H "$AUTH"
```

## Conventions

- Timestamps are RFC3339 UTC strings.
- IDs are UUIDs.
- `is_blocked`/`is_trusted` are the boolean device fields; the UI labels them
  “blocked”/“trusted”.
- All enforcement responses include `verified`; clients must inspect it and
  never treat HTTP 200 alone as success.
- All scan/action endpoints require explicit confirmation.
