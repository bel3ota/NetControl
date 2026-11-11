# Building the Windows installer

Tauri cannot produce a Windows MSI/NSIS installer from a Linux host without a
Windows build environment (WebView2, the MSVC toolchain, and the WiX/NSIS
bundlers are Windows components). The complete CI workflow is included at
`.github/workflows/build-artifacts.yml`; it builds a portable `NetControl.exe` on `windows-latest`.

## Option A: GitHub Actions (recommended)

1. Push the repository to GitHub.
2. The workflow runs on every push and can also be started manually.
3. Download the `netcontrol-windows` artifact:
   - `NetControl.exe` (portable executable)

## Option B: Native Windows build

Prerequisites:

- Windows 10/11 x64
- Rust stable (MSVC toolchain)
- Node.js 22+
- Microsoft Visual Studio Build Tools with the Desktop C++ workload
- WebView2 Runtime (installed on current Windows releases)

From PowerShell:

```powershell
cd apps\desktop
npm ci
npm run tauri build -- --bundles nsis,msi
```

Installers are written to:

```
apps\desktop\src-tauri\target\release\bundle\msi\
apps\desktop\src-tauri\target\release\bundle\nsis\
```

## Notes

- The desktop application runs the shared Rust engine locally and stores its
  database under `%APPDATA%\netcontrol` (or `NETCONTROL_HOME` if set).
- Windows discovery uses the same pnet interface enumeration plus PowerShell
  `Get-NetIPConfiguration` for gateway/DNS metadata, ARP table parsing, ICMP and
  mDNS. It does not include a privileged helper; enforcement is performed by an
  authorized gateway (Linux/OpenWrt/RouterOS/UniFi/pfSense/OPNsense).
- Code signing is intentionally not configured. Add your certificate to the
  workflow before distributing installers publicly.
