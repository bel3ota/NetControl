# Development guide

## Toolchain

- Rust 1.99 (workspace `rust-version = 1.82`)
- Node 26 / npm 11 for the desktop UI
- JDK 21, Android SDK 35, Build-Tools 35.0.0, Gradle 8.14.3 for Android
- Linux kernel with nftables/tc for enforcement tests

## Workspace commands

```bash
cargo check --workspace
cargo test -p netcontrol-core -p netcontrol-discovery -p netcontrol-gateway -p netcontrol-service
cargo build --release -p netcontrol-cli -p netcontrol-helper
```

`cargo test --workspace` also builds the Tauri crate; on a headless host prefer
the per-crate commands above.

Live discovery helpers:

```bash
cargo run -p netcontrol-discovery --example live_scan -- wlp2s0
NETCONTROL_SCAN_PORTS=1 cargo run -p netcontrol-discovery --example live_scan -- enp1s0f1
cargo run -p netcontrol-discovery --example mdns_probe -- 192.168.18.63
```

The `live_scan` example prints interfaces, tools, methods, hosts, vendors,
categories and warnings. It performs real probes; run it only on networks you
are authorized to scan.

## Repository map

| Path | Responsibility |
| --- | --- |
| `crates/netcontrol-core/src/models.rs` | shared wire/domain model |
| `crates/netcontrol-core/src/db.rs` | persistence, migrations, queries |
| `crates/netcontrol-core/src/security.rs` | Argon2, AES-GCM, token hashing |
| `crates/netcontrol-core/src/classify.rs` | vendor/hostname/service heuristics |
| `crates/netcontrol-discovery/src/interfaces.rs` | OS interface detection |
| `crates/netcontrol-discovery/src/scanner.rs` | discovery orchestration |
| `crates/netcontrol-gateway/src/*` | adapters and verification |
| `crates/netcontrol-service/src/orchestration.rs` | scan/device/enforcement transactions |
| `crates/netcontrol-service/src/api.rs` | REST handlers, SSE, CORS |
| `crates/netcontrol-cli/src/main.rs` | CLI, local/remote modes, interactive loop |
| `crates/netcontrol-helper/src/main.rs` | privileged JSON allowlist |
| `apps/desktop/src` | React UI |
| `apps/desktop/src-tauri/src/lib.rs` | Tauri commands over shared service |
| `apps/android/app/src/main/java/dev/netcontrol/app` | Compose client |

## Adding a gateway adapter

1. Add a module under `crates/netcontrol-gateway/src/`.
2. Implement `GatewayAdapter` (see `traits.rs`).
3. `probe()` should report static capabilities even when the device is
   unreachable; `ok` indicates readiness, not feature support.
4. Every mutation must read back the gateway state and set `verified`.
5. Return `EnforcementResult::unsupported` for features the adapter does not
   implement — never a fake success.
6. Add the factory arm in `lib.rs`.
7. Add unit tests for framing/parsing/generated arguments. If possible, provide
   an integration test with a mock server.
8. Document required credentials, transport, privileges and limitations.

### Command safety

- Never build a shell command from user input.
- Use argument vectors for local tools.
- Use validated values and quote remote SSH script values with `sh_quote`.
- Redact secrets before logging; `redact_for_log` is applied by audit writes.

## Database changes

Add a numbered SQL file under `crates/netcontrol-core/migrations/` and append it
to `MIGRATIONS` in `db.rs`. Migrations run in a transaction and are recorded in
`schema_migrations`. Keep migrations forward-only and test both a fresh DB and
an upgrade from the previous schema.

## API changes

- Add the route in `api.rs` and, if applicable, the shared orchestration function.
- Mirror the command in `apps/desktop/src-tauri/src/lib.rs` and `src/api.ts` if
  the desktop UI should expose it.
- Update `docs/openapi.json` and `docs/API.md`.
- Add or update the integration test in `crates/netcontrol-service/tests/api.rs`.

## Desktop UI

```bash
cd apps/desktop
npm ci
npm run dev       # browser mode (API client)
npm run tauri dev # native local engine
npm run build     # TypeScript + Vite production build
```

Browser mode is useful for screenshots and remote management; Tauri mode calls
the local engine. `src/api.ts` switches automatically on
`__TAURI_INTERNALS__`.

Design rules:

- dark default, no generic admin template;
- mint accent reserved for verified/active states;
- amber for “unsupported/not ready”, rose for failed/blocked;
- never show a blocked/limited state before `result.verified`;
- every asynchronous action has loading/error/empty states.

## Android

```bash
cd apps/android
export JAVA_HOME=$HOME/opt/jdk21
export ANDROID_HOME=$HOME/Android/Sdk
./gradlew assembleDebug
```

The client lives entirely in `data/` (models, secure store, API) and `ui/`
(Compose screens). It does not contain a second discovery engine. Session tokens
are sealed with the Android Keystore.

## Screenshots

Desktop screenshots are generated with Playwright against the running service:

```bash
cd apps/desktop
npm run preview -- --port 4173 &
node shots.mjs
```

Android screenshots are captured from a booted emulator:

```bash
adb exec-out screencap -p > screenshots/android.png
```

The screenshots in this repository were taken against real devices discovered
on the live Wi-Fi/Ethernet networks, not fixtures.

## Release checklist

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings   # optional, may reveal lints
cargo test -p netcontrol-core -p netcontrol-discovery -p netcontrol-gateway -p netcontrol-service
cargo build --release -p netcontrol-cli -p netcontrol-helper

cd apps/desktop && npm ci && npm run build
cd ../android && ./gradlew assembleDebug
```

Package the Arch build with `packaging/arch/PKGBUILD`. Build Windows installers
with the workflow. Verify the APK on at least one physical Android device before
public distribution.

## Known technical debt

- Service database access uses a mutex-guarded SQLite connection; sufficient for
  a single administrator, revisit for multi-tenant deployments.
- Monitoring history is minute-aggregated; raw sample retention is not exposed.
- Router adapters need hardware integration tests.
- Windows discovery needs validation on Windows 10/11 hardware.
- Linux tc statistics are not parsed into per-device monitoring samples.
