# Architecture

## 1. Goals

NetControl is a network management product, not a packet scanner demo. It must:

1. Discover the actual network the host is attached to, on any private IPv4 subnet.
2. Merge multiple discovery signals into one durable device identity.
3. Keep monitoring and access-control semantics identical across CLI, desktop and Android.
4. Enforce access control only where an authorized gateway exists, and verify every change.
5. Never fabricate devices, traffic or enforcement state.

Non-goals: defeating Wi-Fi security, VLAN isolation, client isolation, 802.1X, or any access control not explicitly granted to the administrator. NetControl is not a remote-exploitation tool and does not bypass authentication.

## 2. Shared engine

```
┌─────────────────────────────────────────────────────────────────────┐
│ netcontrol-core                                                     │
│ models · SQLite + migrations · crypto · OUI · classification · util │
└───────────────▲──────────────────────────────────────────▲──────────┘
                │                                          │
┌───────────────┴───────────────┐          ┌───────────────┴──────────┐
│ netcontrol-discovery          │          │ netcontrol-gateway       │
│ interfaces · ARP · ICMP ·     │          │ trait GatewayAdapter     │
│ mDNS · nmap · orchestration   │          │ Linux · OpenWrt ·        │
└───────────────▲───────────────┘          │ RouterOS · UniFi ·       │
                │                          │ pfSense · OPNsense       │
┌───────────────┴──────────────────────────┴──────────────────────────┐
│ netcontrol-service                                                  │
│ orchestration · auth · REST/SSE · monitor · scheduler · audit       │
└───────▲─────────────────────▲──────────────────────────▲────────────┘
        │ direct library       │ REST/HTTPS               │ REST/HTTPS
┌───────┴────────┐    ┌───────┴────────────┐    ┌────────┴──────────┐
│ netcontrol CLI │    │ Tauri desktop      │    │ Android client    │
│ (local/remote) │    │ (embedded engine)  │    │ (management only) │
└────────────────┘    └────────────────────┘    └───────────────────┘
```

- The **CLI** is the reference local interface. It calls the same `netcontrol-service` orchestration functions directly.
- The **desktop** backend embeds the same state and exposes narrow Tauri commands to the React UI. No networking logic is reimplemented in TypeScript.
- **Android** is a client by design: Android cannot perform raw ARP or control other devices' traffic without root, so it talks to the authenticated service.

## 3. Discovery pipeline

```
InterfaceManager::detect_active
  ├─ pnet interface enumeration (addresses, MAC, flags)
  ├─ /sys/class/net: kind, operstate, speed, driver, USB ancestry
  ├─ /proc/net/route: per-interface IPv4 default gateways (multi-homed aware)
  ├─ /proc/net/ipv6_route: default IPv6 gateway
  ├─ resolvectl dns <iface>: per-link DNS
  └─ iw dev <iface> link: SSID
        │
        ▼
Scope guard (private/ULA/link-local by default; max_hosts)
        │
        ├─ neighbor table (/proc/net/arp + ip -6 neigh)
        ├─ optional arp-scan (root/CAP_NET_RAW)
        ├─ kernel ARP priming (UDP to on-link IPs, no raw sockets)
        ├─ ICMP echo (Linux ping sockets; fallback warning)
        ├─ Nmap host discovery (optional, fixed argv)
        ├─ TCP liveness / explicit ports (bounded concurrency)
        └─ mDNS/DNS-SD (split queries, compressed-name parser)
        │
        ▼
Host map merge → reverse DNS (bounded) → OUI → classifier
        │
        ▼
SQLite upsert by MAC (or IP fallback) + history + offline sweep
        │
        ▼
REST/SSE/CLI events
```

### Identity rules

- The MAC address is the primary key for a device when available.
- Without a MAC, `(ip, interface)` is used for matching; a later observation with a MAC upgrades the record.
- Randomized MACs are labelled as such and vendor lookup is suppressed because OUI is meaningless.
- A device never disappears: going offline only sets `online = 0` and appends history.
- Manual category/name overrides are preserved; automatic classification only fills unknowns.
- The local host is enriched with the interface MAC and classified as a desktop when its IP appears in scan results.

### Why ARP priming

Raw ARP requires `CAP_NET_RAW`. Sending a UDP datagram to each on-link address makes the kernel resolve the neighbor, which is legitimate and unprivileged. The resulting `/proc/net/arp` entries provide MAC addresses. `arp-scan` is used when explicitly requested and privileged.

### Interface semantics

- Multiple default routes are supported; each interface keeps its own gateway.
- Bridges/tun/tap/docker/virtual interfaces are classified separately and hidden from active-network selection.
- Link state uses `operstate`, so administratively-up bridges with no carrier are not reported as active.

## 4. Persistence

SQLite in WAL mode. Migrations are versioned in `netcontrol-core/migrations` and applied transactionally with a `schema_migrations` table.

Tables:

| Table | Purpose |
| --- | --- |
| `networks` | Observed interface/CIDR/gateway/DNS combinations |
| `network_interfaces` | Last-known interface metadata |
| `devices` | Current identity, classification, access and limit state |
| `device_history` | Discovered/online/offline/block/unblock/trust events |
| `scanning_sessions` | Scan lifecycle, methods, host counts, errors |
| `access_rules` | Every block/pause/allow attempt with verification state |
| `bandwidth_rules` | Every limit attempt with verification state |
| `trusted_devices` | Trusted set with timestamps |
| `router_configs` | Gateway configs; secrets sealed separately |
| `monitoring_records` | Measured aggregate and per-device samples |
| `app_settings` | Typed JSON settings |
| `audit_logs` | Actor/action/outcome with redacted detail |
| `users`, `auth_sessions` | Argon2id users and hashed opaque sessions |
| `notifications` | Reserved for persisted notifications |

The `devices` record stores `enforcement` as one of `none/pending/applied/failed/unsupported/expired`. Only an adapter's verified success moves it to `applied`.

## 5. Enforcement contract

```rust
#[async_trait]
pub trait GatewayAdapter: Send + Sync {
    fn capabilities(&self) -> GatewayCapabilities;
    async fn probe(&self) -> Result<GatewayProbe>;
    async fn clients(&self) -> Result<Vec<GatewayClient>>;
    async fn block(&self, target: &Target, expires_at: Option<&str>) -> Result<EnforcementResult>;
    async fn unblock(&self, target: &Target) -> Result<EnforcementResult>;
    async fn set_bandwidth(&self, target: &Target, limit: &BandwidthLimit) -> Result<EnforcementResult>;
    async fn clear_bandwidth(&self, target: &Target) -> Result<EnforcementResult>;
    async fn list_enforced(&self) -> Result<Vec<EnforcedRule>>;
}
```

Every adapter must read the resulting state back:

| Adapter | Verification |
| --- | --- |
| Linux | `nft list set inet netcontrol blocked`; `tc class/filter show` |
| OpenWrt | `uci show firewall` after `commit` + `fw4 reload` |
| RouterOS | address-list/filter/queue `print` |
| UniFi | client `blocked` flag / `usergroup_id` |
| pfSense | `pfctl -sr` |
| OPNsense | alias content + firewall rule search |

`EnforcementResult { success, verified, … }` is only `success = true` when
`verified = true`. On failure, the device record is not changed to blocked/limited;
the `enforcement` field records `failed`/`unsupported` and an access-rule row keeps
the error.

If no gateway is configured, orchestration returns `unsupported` with a clear
message and leaves the device untouched. The UI shows “Discovery only”.

### Capability honesty

Adapters report static capabilities per feature and a separate `ok` from `probe`.
An adapter can support blocking but be unreachable; the UI then shows
“supported / not ready” rather than pretending either that the feature is absent
or that it is active.

### Temporary restrictions

`blocked_until`/`limit_expires_at` are stored. The scheduler polls every 15s,
calls the adapter to remove expired rules, and only clears the DB flag when the
adapter verifies removal. This is why the ACL page distinguishes “expired” from
“removed”.

## 6. Monitoring

- Aggregate interface counters are read from `/proc/net/dev` every 3 seconds.
- Rates are computed from real counter deltas; total bytes are reported as-is.
- History is grouped into one-minute averages for charts.
- Per-device traffic is only recorded when a gateway reports client counters or
  byte totals; otherwise `source = unavailable` and the UI explicitly says so.
- No synthetic series, interpolation or “estimated” values are presented as
  measured. The model supports `measured`, `gateway`, `estimated`, `unavailable`,
  but no code path writes `estimated` today.

## 7. Service and authentication

- Axum REST API, default `127.0.0.1:8787`.
- Login: Argon2id verification, per-IP rate limit (15 failures / 5 min), opaque
  32-byte token, SHA-256 digest stored, 12h TTL (configurable).
- Bearer or `X-API-Token`; SSE accepts `?token=` because EventSource cannot set
  headers.
- Roles: `admin` for mutations, `viewer` for reads. Every mutation is audited.
- CORS allowlist for Tauri/dev origins, no wildcard with credentials.
- Body limit 1 MiB, security headers (`nosniff`, `DENY`, no-referrer).
- TLS via rustls when `tls_cert/tls_key` are configured. Non-loopback listeners
  without TLS are refused unless an explicit lab override is set.
- SSE broadcasts device discovery, scan completion, monitoring samples,
  enforcement results and notifications.

## 8. Privilege model

| Component | Privilege | Why |
| --- | --- | --- |
| CLI/discovery/service | normal user | unprivileged discovery works |
| `netcontrol-helper` | root via sudo | nftables and tc require CAP_NET_ADMIN |
| Android | none | management only |
| Gateway adapters | configured credentials | least-privilege API/SSH user recommended |

The helper accepts one JSON object on stdin and only these actions:
`status`, `block`, `unblock`, `set_limit`, `clear_limit`, `list`.
It validates IPv4 scope, interface names, rates and priorities, generates nft
scripts and tc argument vectors (never a shell), and runs only as root.

## 9. Failure semantics

| Failure | Result |
| --- | --- |
| No gateway configured | `unsupported`, no device change |
| Adapter unreachable/auth failure | `failed`, no device change, audit entry |
| Adapter accepts but read-back mismatches | `verified = false`, no device change |
| ICMP unavailable | warning; ARP/mDNS/nmap results continue |
| Nmap missing | warning; scan continues |
| mDNS no responses | method omitted; no fabricated hostnames |
| Scan scope violates private-range guard | `403`, no packets sent |
| Scan without confirmation | rejected |
| Session expired/revoked | `401`, client returns to login |
| Gateway credential decryption failure | operation fails; secret never logged |

## 10. Extensibility

To add an adapter:

1. Implement `GatewayAdapter` in `crates/netcontrol-gateway/src`.
2. Add the enum variant and factory arm.
3. Verify every mutation by reading state back.
4. Declare capabilities honestly; ensure unsupported operations return an
   explicit `unsupported` result.
5. Add protocol/command unit tests; validate against real hardware before
   claiming production readiness.
6. Document required privileges, transport and failure modes.

See [DEVELOPMENT.md](DEVELOPMENT.md).
