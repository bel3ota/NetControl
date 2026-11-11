# Screenshots

All screenshots were captured from the running applications against the real
NetControl service and real devices discovered on the test host's Wi-Fi and
Ethernet networks. No fixture data or mock dashboard was used.

| File | Screen |
| --- | --- |
| `01-login.png` | Desktop web UI login |
| `02-dashboard.png` | Desktop dashboard with live measured traffic |
| `03-devices.png` | Desktop device inventory (16 real devices) |
| `04-device-detail.png` | Desktop device drawer |
| `05-monitoring.png` | Desktop traffic monitoring |
| `06-access-control.png` | Desktop trusted-device view |
| `07-gateways.png` | Desktop gateway integrations and capability honesty |
| `08-settings.png` | Desktop settings, security posture, audit |
| `09-block-dialog.png` | Desktop confirmation modal with enforcement warning |
| `10-scan-dialog.png` | Desktop authorized scan dialog |
| `12-android-dashboard.png` | Android dashboard |
| `13-android-devices.png` | Android device inventory |
| `14-android-device-detail.png` | Android device bottom sheet |
| `15-android-access.png` | Android access control (trusted) |
| `16-android-settings.png` | Android settings and gateway state |
| `17-android-scan.png` | Android scan configuration |
| `18-android-scan-result.png` | Android scan completed through the live service |
| `19-android-login.png` | Android login |
| `20-cli.png` | Real CLI output rendered from the terminal capture |

The Android APK was installed and exercised on an Android 35 x86_64 emulator
against the live service. The desktop UI was captured in Chromium against the
same service; the Tauri window was separately compiled and launched on
Omarchy/Wayland (the desktop session locked before a window-only screenshot
could be taken).

Gateway enforcement is deliberately shown as **not ready** in these screenshots
because the host lacks the passwordless helper setup. The Linux nftables/tc
engine itself was verified in an isolated container; see `docs/GATEWAYS.md`.
