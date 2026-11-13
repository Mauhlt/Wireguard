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
| `refpeer.zig` | Minimal one-peer endpoint on the reference model with the same CLI as zwg. `zig build interop` runs the loopback zwg+zwg, refpeer+refpeer and zwg+refpeer (cross-implementation, real processes). |
| `live.zig` | Live interop driver against the installed WireGuard for Windows. |
| `drive.zig`, `ip.zig` | Shared helpers: keys, `.conf` files, processes, IPv4/UDP packets. |

## CLI contract: `zwg up --tun udp:<port>`

The loopback runner and phase B of the live test drive zwg like this:

```
zwg up <conf> --tun udp:<port>
```

* Runs the device in the foreground with `tun.UdpTun.open(<port>, mtu)` as its TUN
  instead of the OS adapter (`UdpTun.parseSpec` parses the argument). Addresses
  and routes are not applied in this mode (`setAddress` / `addRoute` are no-ops
  on UdpTun).
* `zwg` with no arguments prints a usage text that mentions `--tun` (if a
  binary does not, the runner reports `SKIP` for it). Implemented in
  src/main.zig.
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
   (without `--zwg`, phase B is skipped.)
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

## Live test: Windows (Wintun) <-> WSL

Two real hosts: zwg on Windows with a **real Wintun adapter** talks to WSL2,
first to the official **Linux kernel WireGuard**, then to **zwg built for
Linux** on a real `/dev/net/tun`. Unlike the single-host test above, the two
tunnel addresses live on different hosts (Windows and the WSL VM), so every
packet really crosses both implementations and both OS network stacks.

| File | What it is |
|---|---|
| `live_wsl.zig` | `zwg-live-wsl.exe`: the elevated Windows driver. |
| `live_linux.zig` | `zwg-live-linux` (cross-compiled for x86_64 Linux): the WSL side. `serve` is the driver's control channel; `netns-test` is a self-contained kernel-WG <-> zwg test in two network namespaces; `cleanup` removes leftovers. |

Prerequisites: WSL2 with kernel WireGuard (`CONFIG_WIREGUARD=y` in the
Microsoft kernel), `wireguard-tools` (`sudo apt-get install wireguard-tools`),
`iproute2` and `ping` in the distro. No Zig inside WSL is needed: the Linux
binaries are cross-compiled.

1. As your normal user (downloads the signed DLL nowhere; it only copies the
   one you verified):
   ```
   zig build interop-live-wsl -Dwintun=%LOCALAPPDATA%\zwg-deps\wintun
   ```
   (`-Dwintun` / `ZWG_WINTUN_DIR` = the unzipped official release; zig-out\bin
   then holds zwg.exe + wintun.dll + zwg-live-wsl.exe, zig-out\linux the Linux side.)
2. In **Terminal (Admin)**, in the repo:
   ```
   zig-out\bin\zwg-live-wsl.exe
   ```
   (`--quick` skips the two slow checks, ~3 min; results go to
   `zig-out\zwg-live-wsl-results.txt`, or `--out <file>`.)

Topology: Windows `zwgtest` 10.88.0.1/24 (zwg, UDP port picked at start) ;
WSL root namespace: kernel `zwgk0` 10.88.0.2 (UDP 51820), later zwg `zwgz0`
10.88.0.3 (UDP 51821). Endpoints are the WSL VM's eth0 address and the
Windows host address as WSL sees it (its default gateway).

Checks, for each WSL peer: handshake initiated by Windows, handshake
initiated by the WSL peer, UDP echo and ping both ways, MTU-sized (1420-byte,
DF) UDP and ping both ways, endpoint roaming (the WSL peer changes its UDP
port; zwg on Windows must follow from authenticated packets), final `wg show`
style status on both sides. Kernel only: forced re-handshake (`wg set peer
remove/re-add`), and without `--quick` a dead-session re-handshake driven by
zwg's timers (~15 s) and zwg's time-based rekey after REKEY_AFTER_TIME (~120 s).

Changed, and removed again on success and on failure: three inbound firewall
rules `zwg-live-wsl-{wg,echo,icmp}`, the Wintun adapter `zwgtest` (`zwg
down`), `%TEMP%\zwgtest.conf` (overwritten, deleted) and `zwgtest.log`; inside
WSL the `zwgk0` / `zwgz0` interfaces, the echo server and `/run/zwg-live`
(root-only key files, overwritten before deletion). If a run is interrupted,
running it again cleans up first; `wsl -u root -e zig-out/linux/zwg-live-linux
cleanup` does the WSL half by hand.

WSL-only variant, no Windows elevation (needs root inside WSL):
```
zig build interop-live-linux
wsl -u root -e zig-out/linux/zwg-live-linux netns-test --zwg zig-out/linux/zwg [--quick] --out <file>
```
Namespaces `zwg-live-k` (kernel WireGuard) and `zwg-live-z` (zwg) joined by a
veth pair; the same checks plus roaming of zwg's source address. Recorded
results: `results/wsl-netns-*.txt`.

## Fuzzing

`src/fuzz.zig` (and `src/noise/tests.zig`) hold `std.testing.fuzz` targets:
noise message parsers / consumers (with valid MAC1 half the time), `.conf`
parser (round trip), keys / addresses / CIDRs / endpoints (two key decoders
and std.base64 must agree), the allowed-IPs trie against a brute-force model,
transport seal/open, the replay window against an exact model, the TUN packet
paths (packetflow, packet ring, IP header parse) and a real Device fed
valid, mutated and junk datagrams (cryptokey-routing invariants on the TUN
output). `zig build test` runs each once on its corpus. Real coverage-guided
fuzzing needs Linux/macOS (`--fuzz` is not implemented on Windows in this
Zig) and ReleaseSafe (Debug fuzz builds fail with "pcs_len was zero"):
```
zig build test --fuzz=1M -Doptimize=ReleaseSafe -Dtest-filter="fuzz: replay"
```
One process per target (`-Dtest-filter`) gives per-target coverage numbers.

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
