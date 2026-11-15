# Third-party material

All code in this repository is original Zig written for it (see LICENSE). No
third-party source file is included. The work below shaped it, and is
credited here.

## wireguard-go (MIT)

https://git.zx2c4.com/wireguard-go — Copyright (C) 2017-2025 WireGuard LLC.
All Rights Reserved.

`src/session/timers.zig` follows wireguard-go's `device/timers.go` function
by function (the Go names are given in brackets), `src/session/replay.zig`
behaves exactly like its `replay/replay.go` filter (an RFC 6479 bitmap ring
of the same size), and `src/session/constants.zig` takes its values from
`device/constants.go` (marked `[GO]`). Where a port of this logic is a
substantial portion of wireguard-go, it is used under wireguard-go's
license:

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

## Wintun API (wintun.h, GPL-2.0 OR MIT)

https://www.wintun.net — Copyright (C) 2018-2021 WireGuard LLC.

The Wintun function signatures and types in `src/tun/windows.zig` ("Wintun
API (wintun.h, v0.14)") are transcribed from `wintun.h`, used under its MIT
option (the same permission notice as above). `wintun.dll` itself is never
part of this repository or its builds; it is loaded at run time from the
official signed release after an Authenticode check.

## Linux kernel WireGuard (GPL-2.0), reference only

`drivers/net/wireguard` in the Linux kernel. No kernel source is included or
translated. Comments name the kernel functions whose behaviour this code
matches (`noise.c`, `cookie.c`, `receive.c`, `send.c`, `timers.c`,
`ratelimiter.c`, `allowedips.c`, constants marked `[LK]`), so the two can be
compared; protocol constants are taken from the specification and checked
against the kernel's published values.

## The WireGuard protocol

The handshake, transport and cookie formats are implemented from the
protocol description at https://www.wireguard.com/protocol/ and the
whitepaper ("WireGuard: Next Generation Kernel Network Tunnel", Jason A.
Donenfeld). "WireGuard" is a registered trademark of Jason A. Donenfeld;
this project is not affiliated with or endorsed by him or WireGuard LLC.

## Test vectors

Known-answer tests use published vectors:

- RFC 7748 section 6.1 (X25519, Alice/Bob) — `src/crypto.zig`,
  `tests/interop/golden.zig`
- RFC 7693 appendix B (BLAKE2s-256 "abc") — `src/crypto.zig`
- RFC 8439 section 2.8.2 (ChaCha20-Poly1305 AEAD) — `src/crypto.zig`
- draft-irtf-cfrg-xchacha-03 appendix A.3.1 (XChaCha20-Poly1305) —
  `src/crypto.zig`

RFC text and its code components: Copyright (c) IETF Trust and the persons
identified as the document authors; code components are available under the
Revised BSD License (IETF Trust Legal Provisions, section 4). The initial
chaining key and hash are the values the protocol defines
(HASH(construction), HASH(ck || identifier)), compared with the Linux
kernel's constants. The X25519 public keys in `tests/interop/golden.zig`
are `wg pubkey` output for throwaway test keys.

## Algorithms from standards

The TCP/IP stack in `src/netstack` implements published standards from
their texts (RFC 9293, 6298, 5681, 6582, 3042, 5827, 2018, 6675, 2883,
3708, 8985, 7323, 6528, 5961, 6691, 6928, 1122 and others named in the
code); the replay window follows RFC 6479.
