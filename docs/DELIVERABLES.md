# Deliverables checklist

| # | Deliverable | Status | Location |
| --- | --- | --- | --- |
| 1 | Complete source code | ✅ | repository root (`crates/`, `apps/`, `docs/`, `packaging/`) |
| 2 | Windows installer (.exe/.msi) | ⚠ Not buildable on this Linux host; workflow + instructions supplied | `.github/workflows/windows.yml`, `packaging/windows/BUILD.md` |
| 3 | Omarchy/Arch CLI executable | ✅ `netcontrol-linux-x86_64` | `deliverables/` |
| 4 | Arch package / PKGBUILD | ✅ `netcontrol-0.1.0-1-x86_64.pkg.tar.zst` + PKGBUILD | `deliverables/`, `packaging/arch/` |
| 5 | Android APK | ✅ debug-signed, emulator-tested | `deliverables/netcontrol-android-debug.apk` |
| 6 | Database migrations | ✅ embedded + SQL | `crates/netcontrol-core/migrations/` |
| 7 | API documentation | ✅ | `docs/API.md`, `docs/openapi.json` |
| 8 | Installation guides | ✅ Arch/Omarchy, service, desktop, Windows, Android | `docs/INSTALL.md` |
| 9 | Configuration examples | ✅ | `packaging/config.example.toml`, `packaging/netcontrol.service`, `packaging/sudoers.netcontrol` |
| 10 | Automated tests | ✅ 52 Rust tests + 3 Android unit tests | see README / `cargo test` |
| 11 | Developer documentation | ✅ | `docs/DEVELOPMENT.md`, `docs/ARCHITECTURE.md` |
| 12 | Screenshots of actual applications | ✅ desktop + Android + CLI | `screenshots/` |

## Verification evidence

- Live scan: Wi-Fi `192.168.137.0/24` and Ethernet `192.168.18.0/24` discovered
  real hosts with MACs, OUI vendors and categories (neighbor + ICMP + mDNS).
- Service: authenticated HTTP login, scan, dashboard, device state, audit; TLS
  listener tested with a self-signed certificate.
- Enforcement contract: API integration test proves a block without a gateway
  returns `unsupported`, persists `is_blocked=false`, and records the failure.
- Linux enforcement: nftables block, tc HTB/police limit, unblock and clear were
  executed and verified in an Arch container with `CAP_NET_ADMIN`.
- Android: APK installed on Android 35 emulator, signed in over HTTP to the live
  service, scanned the real network, and displayed the result.
- Desktop: UI screenshots generated from the live API; Tauri window launched on
  Omarchy/Wayland.

## Not claimed

- Physical-router validation for OpenWrt/MikroTik/UniFi/pfSense/OPNsense.
- A Windows binary built in this environment.
- Public-internet scanning or bypassing network isolation.
