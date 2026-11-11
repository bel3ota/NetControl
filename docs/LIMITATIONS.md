# Limitations and support matrix

NetControl is deliberately honest about what it can and cannot do. This file is
the authoritative list of constraints; the UI mirrors these distinctions.

## Build / verification status

| Deliverable | Status in this workspace |
| --- | --- |
| Rust engine, CLI, service | Built and exercised on Omarchy/Arch (Linux 7.2, Rust 1.99) |
| Linux nftables/tc enforcement | Executed and verified inside a capability-isolated Arch container |
| Desktop React UI | Built and exercised against the live API; screenshots included |
| Tauri desktop binary | Compiles and launches on Omarchy/Wayland (window observed) |
| Windows MSI/EXE | **Not built here** (Linux host); source + GitHub Actions workflow + exact Windows build instructions included |
| Android APK | Built with SDK 35; installed and exercised on an Android 35 emulator against the live service |
| OpenWrt/MikroTik/UniFi/pfSense/OPNsense | Adapters implemented and unit-tested at protocol/command/parse level; **not validated against physical routers in this workspace** |
| Physical phone | Emulator only; APK is installable on Android 8.0+ |

## Android

- Android cannot perform raw ARP or control other devices' traffic; no root is
  used. The app is a management client and requires a reachable NetControl
  service.
- Only total interface traffic can be measured by the service; per-device rates
  require a gateway that reports counters (for example UniFi).
- The supplied APK is a debug build. Production distribution requires a release
  keystore and ideally Play Integrity/attestation.
- Cleartext HTTP is allowed for local setup and explicitly warned about; Android
  system trust rejects self-signed HTTPS certificates unless a CA is installed.
- Scanning from the app executes on the service host, not on the phone.

## Windows desktop

- The Windows installer cannot be produced from this Linux environment. Use the
  included workflow or build on Windows. Do not expect a `.msi` in
  `deliverables/` from this checkout.
- Windows discovery support is implemented with pnet + PowerShell
  `Get-NetIPConfiguration` + ARP parsing; it has not been exercised on Windows
  hardware here. Validate before relying on it.
- There is no Windows privileged enforcement helper; Windows clients manage an
  authorized gateway through the service.

## Discovery

- **ICMP** uses Linux unprivileged datagram ping sockets. If the host disallows
  them, the scanner reports a warning and continues with ARP/mDNS/nmap.
- **ARP** requires root or `CAP_NET_RAW` for raw sweeps. Unprivileged operation
  uses kernel ARP priming (UDP probes) plus the neighbor table; this is real ARP
  but depends on the kernel/network responding.
- **IPv6**: neighbor tables and mDNS are supported. Enumerating a /64 is
  intentionally refused; only /120 or narrower can be expanded.
- **mDNS** depends on multicast being permitted. Client isolation or a firewall
  can suppress it. Queries are split below 512 bytes for compatibility.
- **Nmap** is optional and must be installed. Port results require explicit
  `--ports`/`ports: true`; the scanner does not silently port-scan.
- **MAC randomization** makes vendor attribution meaningless. Such devices are
  labelled “Private (randomized MAC)”.
- Devices behind a router/NAT (not on-link) cannot be discovered by ARP/ICMP
  unless the gateway adapter supplies lease/client data.
- Networks larger than `max_hosts` are refused rather than silently truncated.
- Device classification is heuristic; unknown is preferred over a wrong label.
  Manual overrides are preserved.

## Monitoring

- Aggregate interface counts come from `/proc/net/dev` (Linux). Other platforms
  may have no aggregate reader in this build.
- Per-device bandwidth is only shown when the gateway reports real counters;
  otherwise it is explicitly unavailable. No synthetic per-device rates.
- A one-minute average hides short spikes; raw 3-second samples are not exposed
  by the current API.
- Linux gateway per-device `tc` counters are not yet parsed into per-device
  samples. Use UniFi or extend the adapter.
- History retention defaults to 90 days (`retention_days`).

## Enforcement

- Blocking works only when NetControl is an authorized gateway or connected to
  one through a supported adapter. Otherwise the operation is `unsupported` and
  the device is not modified.
- Linux blocking drops **forwarded** traffic (`inet netcontrol` forward hook). It
  does not police other VLANs, bridged switch ports, or traffic that bypasses
  the gateway.
- Linux bandwidth shaping requires the LAN interface (`interface_hint`). The
  adapter refuses to replace an existing non-NetControl root qdisc.
- OpenWrt temporary blocks rely on the NetControl scheduler to remove the UCI
  rule; native UCI rules have no per-rule timeout.
- pfSense and OPNsense bandwidth automation is not implemented; those adapters
  report the capability as unavailable.
- OPNsense rule creation depends on the installed API version; if the rule
  cannot be created, the operation is rolled back and reported as unsupported.
- UniFi block verification depends on the controller exposing `blocked` for the
  client; without it NetControl reports unverified rather than success.
- One active gateway is selected at a time. Multi-gateway orchestration is not
  implemented.
- The service scheduler removes expired restrictions; if the gateway is
  unreachable, it retries and keeps the restriction visible.

## Security / operations

- No MFA built in; use a VPN/reverse proxy with MFA for internet-facing
  deployments.
- No HA/replication; SQLite is local to the service.
- No Windows service installer for the management daemon; the desktop app runs
  the engine locally or connects to a service.
- No public-internet scanning without an explicit override; this is a feature,
  not a bug.
- Router adapters have not received a formal third-party audit.
- The included Android APK is debug-signed.

## What NetControl will never do

- Claim a device is blocked when the gateway did not confirm it.
- Invent devices, manufacturers, ports, traffic or history.
- Apply local firewall rules and call it “blocking another device”.
- Bypass authentication, Wi-Fi security, VLANs, or router restrictions.
- Scan public address space silently.
- Write router passwords or session tokens to logs.
- Execute arbitrary shell commands from an API request.
