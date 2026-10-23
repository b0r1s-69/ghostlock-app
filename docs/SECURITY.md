# Security and risk

## Authorized use only

GhostLock is a kernel exploit (CVE‑2026‑43499). Use it only on hardware you own and are explicitly authorized to modify. Running it against a device you do not control is unlawful in most jurisdictions and is not supported.

## What can go wrong

- A wrong profile or an unexpected kernel build can corrupt kernel memory, panic, reboot, or lose data.
- The phone may become temporarily unresponsive while the exploit runs.
- A panic can interrupt file writes. Back up important data first.
- The bootloader remains locked; verified boot stays green; root is **temporary**.
- An OTA can replace the kernel and invalidate the profile.

## Test-signed APK

The release APK is signed with a test key:

```
CN=GhostLock Test, O=Test
SHA-256 57484e77dc0dbf74c94516d07ac2c2724e5bde0778991a7454f71babb079db2e
```

It is a convenience build of this source, not an official upstream release. Verify `release/sha256sums.txt` before installing, or build from source using [BUILD-AND-INSTALL.md](BUILD-AND-INSTALL.md).

## Temporary root

The KernelSU LKM is loaded by the rooted child inside the app process (no ADB, no Shizuku
needed) and is not persistent. After every reboot:

- the LKM unloads (a Shizuku server stops too, if one was used).
- The LKM unloads.
- The bootloader remains locked.

Tap **Run** again. Do not expect root at boot.

## Privacy

- No telemetry is added by this port.
- The evidence logs were captured from the test device and contain no LAN IP, ADB pairing code, account name, or serial number.
- The kernel addresses in the logs are per-boot and not sensitive.
- The `tools/scan_adb.py` default host is a placeholder; pass your own phone IP.

## License

Apache License 2.0. The upstream GhostLock license and notices are retained in [LICENSE](../LICENSE). This port is provided **as is**, without warranty of any kind.

## Reporting

Bugs in this port: open an issue in `b0r1s-69/ghostlock-app`. Bugs in the exploit core or the upstream app: report to [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app). Do not publish working exploit details for devices you do not own.
