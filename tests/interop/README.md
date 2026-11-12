# Interop and known-answer harness

```
zig build interop        # golden/KAT tests + two-process loopback (no admin)
zig build interop-live   # builds zig-out\bin\zwg-interop-live.exe (run it elevated, once)
```

| File | What it is |
|---|---|
| `spec.zig` | Independent reference model of the protocol, written from the whitepaper over `std.crypto`. Not production code; its job is to be easy to check against the paper. |
| `golden.zig` | Known-answer tests: X25519 against `wg.exe pubkey` output (and RFC 7748), the initial chaining key / hash against the Linux kernel constants, wire layouts, crypto primitives, then noise + session against `spec.zig` in both roles (handshake, transport data both ways, MAC1, cookie reply / MAC2). |
| `vectors/official.zig` | Transcript recorded from WireGuard for Windows by the live driver. A placeholder (`available = false`) until the live test has been run with `--record`; then the golden tests replay it offline forever. |
| `loopback.zig` | Two peers as two real processes on 127.0.0.1, their TUNs replaced by `UdpTun` sockets the runner feeds and reads; UDP datagrams both ways. |
| `refpeer.zig` | Minimal one-peer endpoint on the reference model with the same CLI as zwg. `zig build interop` runs the loopback against it today. |
| `live.zig` | Live interop driver against the installed WireGuard for Windows. |
| `drive.zig`, `ip.zig` | Shared helpers: keys, `.conf` files, processes, IPv4/UDP packets. |

## CLI contract for zwg (device agent)

The loopback runner and phase B of the live test drive zwg like this:

```
zwg up <conf> --tun udp:<port>
```

* Runs the device in the foreground with `tun.UdpTun.open(<port>, mtu)` as its TUN
  instead of the OS adapter (`UdpTun.parseSpec` parses the argument). Addresses
  and routes are not applied in this mode (`setAddress` / `addRoute` are no-ops
  on UdpTun).
* `zwg` with no arguments prints a usage text that mentions `--tun`. Until it
  does, `zig build interop` reports `SKIP` for the zwg loopback (the refpeer
  loopback still runs).
* The process is ended with a kill (TerminateProcess / SIGKILL) at the end of
  the test.

UdpTun is test-only: it binds 127.0.0.1, drops datagrams from any other
source, and sends TUN output to whoever last sent to it (drivers register with
an empty "hello" datagram).

## Live interop with WireGuard for Windows

Prerequisites: WireGuard for Windows installed in `C:\Program Files\WireGuard`
(`wireguard.exe`, `wg.exe`). Nothing else: the live test needs neither Wintun
nor zwg for phase A.

One admin prompt, one command:

1. Build as your normal user: `zig build interop-live` (and `zig build` for zwg).
2. Open **Terminal (Admin)** in the repo and run
   ```
   zig-out\bin\zwg-interop-live.exe --record tests\interop\vectors\official.zig --zwg zig-out\bin\zwg.exe
   ```
   (`--zwg` only once the device is merged; without it phase B is skipped.)
3. Commit the recorded `tests/interop/vectors/official.zig` (throwaway keys).
   From then on `zig build interop` checks noise/session against bytes the
   official implementation produced, without admin.

What the driver does, step by step:

1. Refuses to run unless elevated (changes nothing).
2. Generates two key pairs (official side, our side) and two free 127.0.0.1 ports.
3. Writes `%TEMP%\zwgtest.conf`: `Address = 10.77.0.1/24`, `ListenPort`, peer =
   our public key, `AllowedIPs = 10.77.0.2/32`, `Endpoint = 127.0.0.1:<our port>`,
   `PersistentKeepalive = 25` (so the service initiates immediately).
4. Binds our UDP port, then `wireguard.exe /installtunnelservice %TEMP%\zwgtest.conf`
   (service `WireGuardTunnel$zwgtest`).
5. Adds a firewall rule allowing inbound UDP to 10.77.0.1:7777 (the echo socket).
6. **Phase A** — receives the official handshake initiation, verifies it with the
   reference model (MAC1, static key, timestamp), answers with a response,
   decrypts the official keepalive, checks `wg.exe show zwgtest latest-handshakes`,
   then sends an encrypted IPv4/UDP datagram 10.77.0.2:40000 → 10.77.0.1:7777.
   Windows delivers it to the driver's echo socket, the echo goes back through the
   official tunnel, and the driver decrypts it. With `--record`, writes the transcript.
7. **Phase B** (`--zwg`) — releases our port and starts
   `zwg up <peer conf> --tun udp:<port>` with the same private key; pushes the
   same datagram into zwg's TUN. zwg must initiate the handshake (the other
   direction from phase A), the echo must come back out of zwg's TUN, and
   `wg show` must report the handshake.
8. Teardown on success and on failure: kill zwg, delete the firewall rule,
   `wireguard.exe /uninstalltunnelservice zwgtest`, overwrite and delete both
   `.conf` files.

Manual equivalent (if you prefer to watch each step): steps 3-5 as commands,
then `wg show zwgtest` in another elevated prompt while the driver runs.

Phase B with a real Wintun adapter instead of UdpTun is deliberately not part
of this test: on a single host both tunnel addresses would be local and
Windows would short-circuit the traffic over loopback, never touching either
tunnel. UdpTun keeps zwg's side of the traffic out of the Windows stack, so
every packet really crosses both WireGuard implementations.

## Wintun (Windows TUN)

The one non-Zig runtime component: a layer-3 adapter on Windows needs a signed
kernel driver, so zwg uses Wintun (WireGuard LLC). `src/tun/windows.zig` loads
`wintun.dll` at runtime from the application directory or System32 only
(`LoadLibraryExW` with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
LOAD_LIBRARY_SEARCH_SYSTEM32`). It is never committed or shipped: download the
signed release from <https://www.wintun.net/> (wintun-0.14.1.zip), check the
SHA-256 published there, and copy `wintun\bin\<arch>\wintun.dll` next to `zwg.exe`.

## Elevation design

Creating a Wintun adapter, opening its session (the device object is
SYSTEM/Administrators only) and adding addresses/routes all require an elevated
token, so the data plane must run elevated; an elevated helper that only
creates the adapter does not help, because the unelevated process could not
open the session afterwards.

Options considered:

1. **`zwg up` from an elevated prompt.** Works today: `Wintun.open` checks
   `TokenElevation` first and returns `error.AccessDenied` (zwg prints
   `tun.windows.elevation_hint`). Fine for development and the interop test.
2. **Self-elevating `zwg up`** (ShellExecuteEx "runas" of itself). A UAC prompt on
   every `up`, and an elevated process with the user's whole environment.
3. **Tunnel service (proposed).** `zwg installtunnel <conf>` (one UAC prompt via
   "runas") registers a per-tunnel Windows service that runs `zwg` as LocalSystem
   with only the data plane, exactly like `wireguard.exe /installtunnelservice`.
   Unelevated `zwg show/down` talk to it over a named pipe whose DACL admits
   SYSTEM, Administrators and the installing user, using the cross-platform
   `wg` UAPI text protocol. The service needs no network access beyond its UDP
   socket and holds the private key only in memory (the .conf is stored with a
   SYSTEM-only DACL).

Recommendation: ship (1) now, build (3) for real use. It keeps the Portal rule —
nothing the user launches runs elevated by default — and matches how the official
client is deployed, so the owner's mental model carries over.
