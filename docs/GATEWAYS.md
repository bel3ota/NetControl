# Gateway integrations

NetControl enforces access rules only through infrastructure you are authorized
to administer. The adapter layer is the boundary between “we observed something”
and “we changed something”. Every mutation must be read back from the gateway
before it is stored as enforced.

## Capability matrix

| Adapter | Transport | Clients | Block | Bandwidth | Priority | Traffic stats | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Linux gateway** | in-process helper (nftables + tc) | ARP + dnsmasq leases | ✅ | ✅ | ✅ | ❌ (aggregate measured separately) | **Executed & verified in a container lab** |
| **OpenWrt** | SSH (Dropbear/OpenSSH) + UCI/fw4 + tc | DHCP leases + ARP | ✅ | ✅ with `interface_hint` | ✅ with shaping | ❌ | Protocol/command tests; hardware validation required |
| **MikroTik RouterOS** | Native API / API-SSL | DHCP leases + ARP | ✅ | ✅ simple queues | ✅ | ❌ | Protocol tests; hardware validation required |
| **UniFi Network** | HTTPS controller API | Controller clients | ✅ | ✅ user-group QoS | ❌ | ✅ client counters | Parsing tests; controller validation required |
| **pfSense** | SSH + easyrule/pfctl | ARP | ✅ | ❌ not automated | ❌ | ❌ | Parse/command tests; firewall validation required |
| **OPNsense** | HTTPS REST API | ARP | ✅ via alias + rule | ❌ not automated | ❌ | ❌ | Parse/rule tests; firewall validation required |

“Not automated” means the adapter reports the capability as unsupported and the
UI never claims the limit is active.

## Common semantics

- **Target**: IP preferred, MAC when supported (Linux nftables and pfSense need
  an IP; RouterOS/OpenWrt/UniFi accept MAC; OPNsense needs IP).
- **Verification**: the adapter reads the resulting gateway state and sets
  `EnforcementResult.verified` accordingly. Only verified results move the
  device to `blocked/limited`.
- **Temporary rules**: `expires_at` is passed to adapters that support it
  (RouterOS address-list timeout, nftables set timeout). For adapters that do
  not, the NetControl scheduler removes the rule when the timer expires and
  verifies removal. The `blocked_until`/`limit_expires_at` fields remain the
  source of truth.
- **Secrets**: encrypted with AES-256-GCM at rest. The API never returns them.
  Audit logs redact them.
- **Idempotence**: rules are named/commented with the target key; repeated
  operations replace the previous rule rather than stacking.

## Linux gateway (this host)

### Requirements

- Root or the installed helper:
  - `/usr/lib/netcontrol/netcontrol-helper` mode 0755, owned by root
  - sudoers rule for the service user
- `nftables` and `iproute2`
- The interface facing the **LAN** must be supplied as `interface_hint` for
  bandwidth shaping. Blocking does not require it.

### What is enforced

Blocking:

```nft
table inet netcontrol {
  set blocked {
    type ipv4_addr
    flags timeout
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr @blocked drop
    ip daddr @blocked drop
  }
}
```

This drops forwarded traffic to/from the device. It is the correct hook when the
Linux host is the router/gateway. It does **not** police bridged traffic on a
switch; in that topology use the switch/AP adapter (UniFi/OpenWrt) instead.

Bandwidth:

- Download: HTB class on the LAN egress (`tc class … rate <down>kbit`), u32
  filter matching destination `/32`.
- Upload: ingress police filter matching source `/32`.
- The adapter refuses to replace an existing non-NetControl root qdisc
  (`mq`, `cake`, `hfsc`, ...) to avoid destroying existing QoS.
- Priority maps to the HTB class `prio` 0–7.

### Setup

```bash
sudo install -Dm755 target/release/netcontrol-helper \
  /usr/lib/netcontrol/netcontrol-helper
echo "$(id -un) ALL=(root) NOPASSWD: /usr/lib/netcontrol/netcontrol-helper" |
  sudo tee /etc/sudoers.d/netcontrol >/dev/null
sudo chmod 0440 /etc/sudoers.d/netcontrol

netcontrol gateway add --kind linux --host local --interface enp1s0f1
netcontrol gateway test
```

A successful probe returns capabilities for block/bandwidth/priority. A probe
that cannot execute the helper keeps those capabilities visible but marks the
gateway `ok = false` and explains that the helper/sudoers rule is missing.

### Test evidence

Inside a `archlinux` container with only `CAP_NET_ADMIN` and a dummy LAN
(`10.99.0.1/24`):

```
status      → ok, nft available
block       → verified: 10.99.0.50 present in inet netcontrol blocked
set_limit   → verified: tc htb 1:50 + ingress police filter present
list        → block rule reported
unblock     → verified: element removed
clear_limit → verified: tc class/filter removed
```

This validates the actual nftables/tc implementation against the real kernel.
It does not imply the helper is installed on your host; see setup above.

## OpenWrt

### Requirements

- OpenWrt with `fw4` (or `fw3`) and `tc`
- SSH access from the NetControl service host
- Prefer an SSH key:
  - `~/.ssh/id_ed25519` for the service user; `authorized_keys` on the router
- Password auth requires `sshpass` on the service host

### Setup

```bash
netcontrol gateway add \
  --kind openwrt --host 192.168.1.1 --username root \
  --interface br-lan
netcontrol gateway test
```

- Blocking: creates a persistent UCI firewall rule named
  `netcontrol_block_<mac-or-ip>` in the `lan → wan` direction with `REJECT`,
  commits and reloads the firewall. Verification reads `uci show firewall`.
- Bandwidth: tc HTB/police on `interface_hint` (for example `br-lan`). Configure
  it only if you accept changing the router's root qdisc; the adapter refuses
  when an `mq`/`cake`/`hfsc` root qdisc is already present.
- Temporary restrictions are removed by the scheduler unless the adapter supports
  native timeouts.

## MikroTik RouterOS

### Requirements

- API enabled: `/ip service api` (8728, plaintext) or
  `/ip service api-ssl` (8729, TLS with a certificate)
- A dedicated API user with policy `api,read,write,test` (or least privilege
  equivalent)
- Firewall filter permission for that user

### Setup

```bash
netcontrol gateway add \
  --kind mikrotik --host 192.168.88.1 --port 8729 \
  --username netcontrol --ask-password
```

Use API-SSL; plaintext is available only by explicitly setting `--no-tls` and
should be restricted to a management VLAN.

### What is enforced

- Block: `netcontrol-blocked` address-list entry for the IP plus forward drop
  rules matching the list; MAC targets get `src-mac-address`/`dst-mac-address`
  drop rules. Entries are tagged with `netcontrol:block:<key>`.
- Unblock: removes the specific tagged entries; global drop rules remain.
- Bandwidth: `/queue/simple` named `netcontrol-qos-<key>` with
  `max-limit=<upload>k/<download>k` and priority.
- Verification: address-list/filter/queue `print` output is parsed after each
  change.

## UniFi Network

### Requirements

- Local UniFi Network controller (UniFi OS or legacy)
- Local administrator account
- HTTPS to the controller
- The controller must see the client (MAC required)

### Setup

```bash
netcontrol gateway add \
  --kind unifi --host unifi.local --username admin --ask-password \
  --site default
```

- Block/unblock: `cmd/stamgr` with `block-sta`/`unblock-sta`; verified by reading
  the client's `blocked` field.
- Bandwidth: creates/updates a user group `netcontrol-<mac>` with
  `qos_rate_max_down/up` (Kbps), assigns it with `set-usergroup`, and verifies
  `usergroup_id`.
- Per-client counters (`rx_bytes-r`, `tx_bytes-r`) are used for measured
  per-device monitoring.

## pfSense

### Requirements

- SSH access (key preferred; `sshpass` for password auth)
- `easyrule` available
- `interface_hint` is the firewall interface name, typically `lan`

### Setup

```bash
netcontrol gateway add \
  --kind pfsense --host 192.168.1.1 --username admin \
  --interface lan --ask-password
```

- Block: `easyrule block <iface> <ip>`; verified with `pfctl -sr` (it must show a
  blocking rule containing the address).
- Unblock: `easyrule unblock <iface> <ip>` and verify the rule is gone.
- Bandwidth: not automated — reported as unsupported rather than pretending.

## OPNsense

### Requirements

- HTTPS API enabled
- API key + secret (System → Access → Users → API keys)
- `interface_hint` (default `lan`)
- The API user can manage aliases and firewall rules

### Setup

```bash
netcontrol gateway add \
  --kind opnsense --host 192.168.1.1 --username '<API key>' \
  --ask-password --interface lan
```

- Blocking uses the `netcontrol_blocked` host alias. The adapter creates the
  alias and a LAN block rule if they are missing; if the installed API version
  cannot create the rule, it removes the alias entry and returns
  `unsupported` with a one-time UI instruction.
- Verification requires both the alias address and a matching block rule.
- Bandwidth traffic shaping is not automated (reported unsupported).

## Temporary rules and scheduling

`netcontrol block <ip> --for 2h`:

1. Computes `expires_at` (max 365 days).
2. Passes it to adapters that support native timeouts.
3. Stores the timestamp on the device and in the access-rule record.
4. The scheduler periodically calls unblock and verifies removal for expired
   rules; if removal fails it retries and leaves the block visible.

The same pattern applies to temporary bandwidth limits.

## Least privilege and safety

- Use a dedicated API/SSH account per gateway where possible.
- Prefer TLS for all management transports; `tls_insecure` exists only for
  self-signed device certificates and logs a visible warning in the config.
- Never give the NetControl service interactive shell access beyond the commands
  its adapter needs.
- The Linux helper is the only local privileged component and is allowlisted.
- Test blocking on a lab device first. A verified block is a real network
  change; confirm the target before applying it.
