# Installation

NetControl is developed and tested on **Omarchy 4.0.6 / Arch Linux** with Rust
1.99, Node 26, Android SDK 35 (build-tools 35.0.0) and Android 35 x86_64
emulator. The Windows and Android sections describe exact toolchains; the
Windows installer must be built on Windows.

---

## 1. Arch Linux / Omarchy - from source

### Dependencies

```bash
sudo pacman -S --needed base-devel rust cargo nodejs npm \
  nftables iproute2 openssh nmap
```

Optional but useful:

```bash
sudo pacman -S --needed arp-scan avahi sshpass jq
```

Rust dependencies are vendored through Cargo. Front-end dependencies use npm.

### Build

```bash
git clone <your-repository> netcontrol
cd netcontrol
cargo build --release -p netcontrol-cli -p netcontrol-helper
```

Binaries:

```
target/release/netcontrol
target/release/netcontrol-helper
```

### Install the CLI and helper

```bash
sudo install -Dm755 target/release/netcontrol /usr/local/bin/netcontrol
sudo install -Dm755 target/release/netcontrol-helper \
  /usr/lib/netcontrol/netcontrol-helper
```

Configure the restricted helper. The left-hand side is the account that runs
`netcontrol serve` (your user for interactive use, `netcontrol` for the systemd
unit):

```bash
echo "$(id -un) ALL=(root) NOPASSWD: /usr/lib/netcontrol/netcontrol-helper" |
  sudo tee /etc/sudoers.d/netcontrol >/dev/null
sudo chmod 0440 /etc/sudoers.d/netcontrol
sudo visudo -cf /etc/sudoers.d/netcontrol
```

Verify:

```bash
netcontrol --version
netcontrol interfaces
netcontrol scan --yes
netcontrol devices
```

Discovery works without the helper. Blocking/bandwidth requires the helper and
a configured gateway.

### Run the management service manually

```bash
netcontrol serve --listen 127.0.0.1:8787
```

The first-run administrator password is written to:

```
~/.config/netcontrol/initial-admin-password.txt
```

The file is mode `0600`, is never written to logs, and is deleted after the
first administrator login. Override behavior with:

```bash
NETCONTROL_ADMIN_USER=admin \
NETCONTROL_ADMIN_PASSWORD='a-strong-password' \
netcontrol serve
```

### Remote access with TLS

```bash
# Generate a self-signed certificate for a LAN hostname (example)
openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
  -keyout /etc/netcontrol/server.key -out /etc/netcontrol/server.crt \
  -subj "/CN=netcontrol.lan" \
  -addext "subjectAltName=DNS:netcontrol.lan,IP:192.168.1.10"
sudo chmod 600 /etc/netcontrol/server.key

netcontrol serve --listen 0.0.0.0:8787 \
  --tls-cert /etc/netcontrol/server.crt \
  --tls-key  /etc/netcontrol/server.key \
  --allow-remote
```

The service refuses a non-loopback listener without TLS unless
`NETCONTROL_ALLOW_INSECURE_REMOTE=1` is explicitly set for an isolated lab.
Clients must trust the certificate; use a local CA or a public certificate for
production.

### systemd unit (package install)

The Arch package installs:

- `/usr/lib/systemd/system/netcontrol.service`
- `/usr/lib/sysusers.d/netcontrol.conf`
- `/usr/lib/tmpfiles.d/netcontrol.conf`
- `/etc/sudoers.d/netcontrol`
- `/usr/lib/netcontrol/netcontrol-helper`

Enable:

```bash
sudo systemctl enable --now netcontrol
sudo cat /var/lib/netcontrol/initial-admin-password.txt
sudo journalctl -u netcontrol -f
```

The daemon runs as the unprivileged `netcontrol` user with `NETCONTROL_HOME=/var/lib/netcontrol`.

### Arch package

```bash
cd packaging/arch
makepkg -si
```

The included tarball is the release source; `makepkg` rebuilds the Rust
binaries with `--locked`. If you prefer a clean package, create a source tarball
from your checkout and update `sha256sums` in `PKGBUILD`.

---

## 2. Desktop application

### Development (Linux)

```bash
cd apps/desktop
npm ci
npm run dev          # browser UI at http://127.0.0.1:1420
npm run tauri dev    # native Tauri window
```

The browser UI can sign in to any running service. The Tauri window embeds the
shared engine and stores its database under the platform data directory
(`$XDG_DATA_HOME/netcontrol` on Linux, `%APPDATA%\netcontrol` on Windows).

### Windows installer

Windows requires MSVC Build Tools, WebView2 and the Tauri bundlers. On Windows:

```powershell
cd apps\desktop
npm ci
npm run tauri build
```

Outputs:

```
apps\desktop\src-tauri\target\release\bundle\msi\*.msi
apps\desktop\src-tauri\target\release\bundle\nsis\*.exe
```

A GitHub Actions workflow is included at `.github/workflows/build-artifacts.yml`; run it
manually or on a tag and download the `netcontrol-windows` artifact. The
installer is **not** produced by the Linux development environment used for this
repository. See [../packaging/windows/BUILD.md](../packaging/windows/BUILD.md).

### Linux desktop release bundle (optional)

```bash
cd apps/desktop
npm ci
npm run tauri build -- --bundles deb,appimage
```

---

## 3. Android

### Prerequisites used to build the supplied APK

- JDK 21 (Temurin 21.0.13)
- Android SDK Platform 35, Build-Tools 35.0.0, platform-tools
- Gradle 8.14.3 (the project has a wrapper; a local distribution avoids wrapper
  downloads on slow links)

Install with `sdkmanager`:

```bash
export JAVA_HOME=$HOME/opt/jdk21
export ANDROID_HOME=$HOME/Android/Sdk
yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --licenses
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager \
  "platform-tools" "platforms;android-35" "build-tools;35.0.0"
```

Build:

```bash
cd apps/android
export JAVA_HOME=$HOME/opt/jdk21
export ANDROID_HOME=$HOME/Android/Sdk
./gradlew assembleDebug
```

APK:

```
apps/android/app/build/outputs/apk/debug/app-debug.apk
```

The push-triggered workflow uploads the APK as the
`netcontrol-android-apk` artifact. Install the local build with:

```bash
adb install -r apps/android/app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n dev.netcontrol.app/.MainActivity
```

Sign-in:

- Android emulator: `http://10.0.2.2:8787/api/v1`
- Physical device: `https://<service-host>:8787/api/v1` (preferred) or
  `http://<lan-ip>:8787/api/v1` for a trusted lab. The app displays a cleartext
  warning.

The Android client performs no local enforcement; it authenticates to the
service and uses its REST API. Session tokens are sealed with an Android
Keystore AES-256-GCM key.

Release signing: create a keystore and add `signingConfigs` to
`app/build.gradle.kts`; the supplied APK is a debug build.

---

## 4. First login

1. Start the service.
2. Open the desktop app (or Android) and enter the service URL.
3. Sign in as `admin` with the password from
   `initial-admin-password.txt` (or `NETCONTROL_ADMIN_PASSWORD`).
4. Change the password immediately (API `POST /api/v1/auth/password`).
5. Add a gateway only if you own it and have administrative authority.

---

## 5. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `no active IPv4 network interface found` | Connect Wi-Fi/Ethernet; check `ip -brief addr`. |
| Scan finds few devices | Client isolation, ICMP filtering, sleeping hosts. Enable Nmap or `--ports`, run privileged ARP if authorized. |
| mDNS finds nothing | Multicast blocked or no responders. Confirm with `avahi-browse -art`. |
| `nmap is not installed` | `sudo pacman -S nmap`; enable Nmap explicitly. |
| Block returns `permission denied … sudo` | Install the helper and sudoers rule; verify with `sudo -n /usr/lib/netcontrol/netcontrol-helper` (send JSON on stdin). |
| Block returns `unsupported` | No active gateway or the adapter does not support blocking; discovery only. |
| Gateway probe says TLS handshake failed | RouterOS: enable api-ssl or use the correct port; set `tls_insecure` only for a trusted self-signed device. |
| OpenWrt/pfSense SSH fails | Configure an SSH key for the service user, or install `sshpass` for password auth. |
| Service refuses to bind `0.0.0.0` | Configure TLS and `--allow-remote`; this is intentional. |
| Android TLS error | Use a certificate trusted by Android or a local CA installed on the device. Cleartext is for labs only. |
| `Caller-provided IV not permitted` (Android) | Fixed by using Keystore-generated IVs; rebuild the APK if you see this from an older build. |
| Tauri build fails on Linux | Install `webkit2gtk-4.1`, `libsoup3`, `gtk3` development packages; Omarchy already provides them. |

### Verifying the helper safely

```bash
echo '{"action":"status"}' | sudo /usr/lib/netcontrol/netcontrol-helper
```

Expected output is a JSON object with `"ok": true` and a capabilities/data
payload. The helper refuses to run as an unprivileged user.
