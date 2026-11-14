# Interop and known-answer harness

```
zig build interop         # golden/KAT tests + two-process loopback (no admin)
zig build interop-live    # builds zig-out\bin\zwg-interop-live.exe (run it elevated, once)
zig build interop-service # builds zig-out\bin\zwg-service-live.exe (run it elevated, once)
```

| File | What it is |
|---|---|
| `spec.zig` | Independent reference model of the protocol, written from the whitepaper over `std.crypto`. Not production code; its job is to be easy to check against the paper. |
| `golden.zig` | Known-answer tests: X25519 against `wg.exe pubkey` output (and RFC 7748), the initial chaining key / hash against the Linux kernel constants, wire layouts, crypto primitives, then noise + session against `spec.zig` in both roles (handshake, transport data both ways, MAC1, cookie reply / MAC2). |
| `vectors/official.zig` | Transcript recorded from WireGuard for Windows by the live driver. A placeholder (`available = false`) until the live test has been run with `--record`; then the golden tests replay it offline forever. |
| `loopback.zig` | Two peers as two real processes on 127.0.0.1, their TUNs replaced by `UdpTun` sockets the runner feeds and reads; UDP datagrams both ways. |
| `refpeer.zig` | Minimal one-peer endpoint on the reference model with the same CLI as zwg. `zig build interop` runs the loopback zwg+zwg, refpeer+refpeer and zwg+refpeer (cross-implementation, real processes). |
| `live.zig` | Live interop driver against the installed WireGuard for Windows. |
| `service_live.zig` | End-to-end check of the tunnel service (`zwg installtunnel`), run once elevated; see "Elevation design". |
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
`wintun.dll` at runtime by full path only: next to `zwg.exe`, else System32's
(never the current directory or PATH). Before loading, it opens the file
denying writes and deletes, checks its Authenticode signature through that
handle (`WinVerifyTrust`, generic policy, no network: cached revocation data
only) and requires the signer certificate's CN and O to be `WireGuard LLC`;
the handle stays open until `LoadLibraryExW` has mapped the file, so it cannot
be swapped in between. zwg calls `SetDefaultDllDirectories(System32)` first
thing, so nothing else is ever loaded from the (possibly user-writable)
application directory either. A tampered or unsigned DLL fails with
`error.WintunUntrusted`. It is never committed or shipped: download the
signed release from <https://www.wintun.net/> (wintun-0.14.1.zip), check the
SHA-256 published there, and copy `wintun\bin\<arch>\wintun.dll` next to `zwg.exe`.

## Elevation design

Creating a Wintun adapter, opening its session (the device object is
SYSTEM/Administrators only) and adding addresses/routes all require an elevated
token, so the data plane must run elevated; an elevated helper that only
creates the adapter does not help, because the unelevated process could not
open the session afterwards.

Options considered:

1. **`zwg up` from an elevated prompt.** `Wintun.open` checks `TokenElevation`
   first and returns `error.AccessDenied` (zwg prints
   `tun.windows.elevation_hint`). Kept for development and the interop tests.
2. **Self-elevating `zwg up`** (ShellExecuteEx "runas" of itself). A UAC prompt on
   every `up`, and an elevated process with the user's whole environment. Rejected.
3. **Tunnel service — built (owner decision 2026-11-12), `src/service/`.**
   Nothing the user launches runs elevated; the model is WireGuard for Windows'
   `/installtunnelservice`.

### The tunnel service (`zwg installtunnel`)

```
zwg installtunnel <file.conf> [--auto]   one UAC prompt: install + start
zwg show                                 installed tunnels and their state      (unelevated)
zwg show <name>                          live status over the control pipe      (unelevated)
zwg down <name> / zwg up <name>          stop / start the service               (unelevated, installing user)
zwg uninstalltunnel <name>               one UAC prompt: stop + remove everything
```

**Elevation, once per install/uninstall.** The unelevated `zwg` validates the
.conf, then re-launches itself with ShellExecuteEx "runas" and a narrow internal
verb (`/installtunnel-elevated <abs path> <user SID> <auto>` or
`/uninstalltunnel-elevated <name>`), hidden, and waits on the child's process
handle for its exit code (mapped to a message, including the service's own
failure reason). From an already elevated prompt the same code runs in-process.
The elevated child re-reads and re-validates everything it is handed, and
copies the service's binaries only from handles it holds open denying writes
and deletes: its own zwg.exe, verified to be the very file its running image
was mapped from (`NtAreMappedFilesTheSame`; a running .exe can be renamed
away and replaced), and wintun.dll, verified as above but never loaded by the
elevated installer (the directory it comes from, e.g. zig-out\bin, is
user-writable). The service verifies wintun.dll again before loading it.

**Storage** (`store.zig`):

```
%ProgramFiles%\zwg\                      O:BA, D:PAI (SYSTEM, Administrators: full; inherited)
  tunnels\<name>\tunnel.conf.dpapi       the .conf, DPAPI machine scope + fixed entropy
  tunnels\<name>\zwg.exe, wintun.dll     what the service runs (copied at install)
  logs\<name>.log (+ .old)               bounded to 1 MiB each, never keys
```

The ACL is the access control: no non-admin process can open the files. DPAPI
(`CRYPTPROTECT_LOCAL_MACHINE`) is defence in depth: a copy of the file (backup,
image without the machine's LSA secrets) is ciphertext; machine scope because
the installer (elevated user) writes and the service (SYSTEM) reads. The
service binary is copied into the protected tree so LocalSystem never runs an
executable a user could replace (zig-out\bin is user-writable). %ProgramFiles%
comes from `SHGetKnownFolderPath`, never the environment.

Why %ProgramFiles% (as WireGuard for Windows' `%ProgramFiles%\WireGuard\Data`)
and not %ProgramData%: Users may create folders in %ProgramData%, so a user
could pre-create `%ProgramData%\zwg` and, between the elevated installer's
checks and its writes, swap it for a junction — redirecting what SYSTEM writes
and later runs (zwg.exe) and where the decrypted key goes. Only administrators
(and TrustedInstaller) can create anything in %ProgramFiles%. On top of that the
elevated installer and uninstaller (`store.Dirs`) resolve each store directory
exactly once — the root by path, each subdirectory relative to its verified
parent handle, never through a reparse point (`FILE_FLAG_OPEN_REPARSE_POINT`) —
check that very handle (a plain directory per
`GetFileInformationByHandleEx(FileAttributeTagInfo)`, owner Administrators or
SYSTEM per `GetSecurityInfo`), reset owner and DACL on it (`SetSecurityInfo`),
and keep the handles open without `FILE_SHARE_DELETE` until they are done, so
nothing on the path can be renamed, deleted or replaced meanwhile. The files
(conf, zwg.exe, wintun.dll) are written, wiped and deleted relative to those
handles. An install made by an older zwg under `%ProgramData%\zwg` must be
removed with that older zwg (`zwg uninstalltunnel <name>`) first.

**Service** (`scm.zig`): `zwgTunnel$<name>`, SERVICE_WIN32_OWN_PROCESS,
LocalSystem, demand start (or automatic with `--auto`), depends on Nsi and
TcpIp, binary `"<store>\tunnels\<name>\zwg.exe" /tunnelservice <name> <user SID>`,
service SID type unrestricted (its own SID for firewall rules; a restricted SID
would need write-restricted ACEs on everything Wintun/NSI touch), failure
actions: restart after 2 s, again after 5 s, then stay stopped (counter reset
after a day, also on non-crash failure exits such as DNS not ready at boot).
Its DACL is Windows' default plus the installing user with query
status/config, start, stop, interrogate (not change config, delete, WRITE_DAC):
that is what `zwg down/up <name>` use, unelevated.

**Service process** (`tunnel.zig`, `state.zig`): ServiceMain registers a
control handler and reports START_PENDING (wait hint 30 s, checkpoint per
step), decrypts and parses the conf, resolves endpoints, creates the Wintun
adapter, sets addresses and routes, creates the device, opens the control
pipe, reports RUNNING (accepting STOP and SHUTDOWN), runs the device loop.
STOP/SHUTDOWN set the device's `external_stop` event; then STOP_PENDING,
teardown (closing the adapter removes it with its addresses and routes),
STOPPED with a service-specific exit code naming the reason. A stop that
arrives while starting is remembered (the SCM never sees RUNNING after it
asked to stop). std.log output goes to the tunnel's log.

**Control pipe** (`pipe.zig`, `sddl.zig`): `\\.\pipe\ProtectedPrefix\Administrators\zwg\<name>`
(only Administrators/SYSTEM can create pipes under that prefix, so nobody can
squat the name and impersonate the service to `zwg show`; plus
FILE_FLAG_FIRST_PIPE_INSTANCE and PIPE_REJECT_REMOTE_CLIENTS) with an explicit
DACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120083;;;<user SID>)`: the installing user
gets read/write data only (not FILE_CREATE_PIPE_INSTANCE, WRITE_DAC, ...),
nobody else gets anything, and without a mandatory label nothing below medium
integrity can write. The server runs on its own thread with overlapped I/O,
5 s per client, one client at a time; the device state is snapshotted on the
device's loop thread through `Device.control`, so clients never touch the data
path. Clients connect with identification-level impersonation only.

**Protocol** (`uapi.zig`): the cross-platform `wg` UAPI text protocol
(wireguard.com/xplatform), read-only subset. `get=1` answers `listen_port`,
then per peer `public_key`, `endpoint`, `last_handshake_time_sec/nsec`,
`tx_bytes`, `rx_bytes`, `persistent_keepalive_interval`, `allowed_ip`,
`protocol_version=1`, then `errno=0`. Decision: **no private or preshared key
is ever sent**, to anyone (unlike wg, which returns `private_key` to its
admin-only callers): the callers include the unelevated user, and an admin can
read the stored configuration. The interface public key is sent as the
extension key `zwg_public_key=` (wg's parser ignores unknown keys). `set=1` is
refused with `errno=-1` (configuration changes = reinstall, elevated); anything
else gets `errno=-22`. The client-side decoder is bounded (1 MiB, 256-byte
lines, peer and allowed-IP limits) and treats the response as hostile.

**Uninstall**: stop, wait for the service process to exit, delete the service,
overwrite and delete the stored conf, delete the binaries and the log, remove
the directories that are now empty. The adapter goes away when the service
closes it on stop (uninstall waits for the service process to exit first).

### End-to-end check (run once, elevated)

Prerequisite: `wintun.dll` next to `zig-out\bin\zwg.exe` (see Wintun above) or
in System32. Then, as your normal user `zig build interop-service`, and in
**Terminal (Admin)** in the repo:

```
zig-out\bin\zwg-service-live.exe --zwg zig-out\bin\zwg.exe
```

It installs `zwgTunnel$zwgsvctest` (10.79.0.1/24, peer 10.79.0.2 = a plain
`zwg up --tun udp:<port>` process on 127.0.0.1), checks the store's DACL and
encryption (every store directory under the Program Files known folder, a plain
directory owned by Administrators with the protected DACL; the installer's
verifier `Dirs.openExisting` accepts it; an ordinary user can neither read the
conf nor create anything in the store), then — impersonating an ordinary-user version of your token
(Administrators deny-only, medium integrity) — reads the handshake over the
pipe, sends UDP both ways through the real Wintun adapter, checks another
user is refused, runs `down` and `up`, then `zwg uninstalltunnel` and checks
the service, `%ProgramFiles%\zwg\tunnels\zwgsvctest`, the log and the adapter
are gone. On any failure it uninstalls anyway, kills the peer and shreds both
temporary .conf files in %TEMP%. Source: `service_live.zig` (separate from
`live.zig` so the two can be folded into one live run later).
