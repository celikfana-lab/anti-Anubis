# Anubis Native Solver — Firefox Extension

**A Firefox WebExtension that solves [Anubis](https://github.com/TecharoHQ/anubis) anti-bot proof-of-work challenges with native C code over native messaging — no browser JS/WASM solver, no waiting on `Calculating…`.**

`Anubis solver` · `Anubis bypass` · `Firefox extension` · `native messaging` · `proof of work` · `anti-bot` · `git.ffmpeg.org`

Anubis normally makes your browser hash the challenge in JavaScript/WebAssembly.
This add-on detects the challenge page, passes the challenge JSON to a small
statically-linked C host, and navigates straight to the `pass-challenge` URL.
On a `fast` difficulty-6 challenge it finishes in **~74–555 ms** under a 1080p60
video load, where the page's own solver needs **~74 seconds** at ~225 kH/s.

---

## Features

- **Native C solver** via Firefox native messaging (`runtime.sendNativeMessage`).
- **No page JS solver flash** — the challenge UI is masked with a
  `Solving natively…` overlay and Anubis' `main.mjs` is told to stand down
  (`window.__anubisBooted`).
- **8-thread nonce search** with SHA-256 midstate precomputation.
- Handles every Anubis challenge type in the open-source server:
  `fast` / `slow`, `sha256`, `argon2id`, `hashx`, plus `metarefresh` and the
  `css-load` extension.
- **Automatic fallback**: if the host is missing, fails, or cannot do
  `argon2id`, the page reloads and Anubis' normal JS/WASM solver runs. You never
  get stuck.
- **Page-world navigation** so `Partitioned` (CHIPS) verification cookies are
  sent correctly on the `pass-challenge` request.
- Works with regular Firefox and **snap Firefox** (static host for core24).
- Keeps the browser's own cookies/session; no proxy, no TLS interception.

## Benchmarks

Tested against real Anubis (`git.ffmpeg.org`, v1.28.1), 8 threads, i7-1260P:

| Challenge | Firefox page solver | This extension |
|---|---|---|
| `fast` d6 | ~74 s (225 kH/s) | **74.3 / 265.2 / 555.6 ms** (three runs, 1080p60 video playing) |
| `sha256` d24 | seconds | **~0.25 s** |
| `argon2id` d6 | seconds | **~0.8 s** |
| `hashx` d20 | seconds | **0.04–1 s** (nonce-dependent) |
| `metarefresh` | time-gated | time-gated, same |

**Compiler flags:** the native host is built with `-O3`. The measured gain over
`-O2` is small (~3–6% on the `fast` SHA-256 loop, neutral on `hashx`/`argon2id`);
the hot path is OpenSSL's SHA-NI assembly plus the 8-thread/midstate design, not
the C optimizer. `-march=native`/LTO did not help consistently on Alder Lake.

Solve time is dominated by the random winning nonce, so expect variance. The
host logs every solve to `~/anubis-native.log`:

```
2026-10-17 14:24:17 url=https://git.ffmpeg.org/ffmpeg.git?demo=2 algo=fast diff=6 solve_ms=555.6 ok=1
```

## How it works

```
Anubis challenge page
  └─ content.js (document_start)
       ├─ sets window.__anubisBooted = true   ← stops the page's 8 JS workers
       ├─ masks the challenge UI with "Solving natively…"
       ├─ reads #anubis_challenge + #anubis_base_prefix
       └─ background.js ──sendNativeMessage──► anubis_native (static C host)
                                                  ├─ 8-thread PoW
                                                  ├─ midstate SHA-256
                                                  ├─ css-load probe URL
                                                  └─ metarefresh delay
       ◄─ { passUrl, cssUrl, delayMs }
  └─ page-world location.replace(passUrl)        ← browser keeps its cookies
```

The host is a normal native-messaging app: a 4-byte little-endian length
followed by UTF-8 JSON on stdin/stdout.

## Supported challenges

| Algorithm | Native host |
|---|---|
| `fast` / `slow` | ✅ midstate + 8 threads |
| `sha256` | ✅ midstate + 8 threads |
| `hashx` | ✅ 8 threads |
| `argon2id` | ✅ if the static OpenSSL build has the Argon2 provider, otherwise fallback |
| `metarefresh` | ✅ timed pass URL |
| `css-load` extension | ✅ probe fetched before the pass |

Threads: `FB_ANUBIS_THREADS` (default **8**, max 64).

## Install

Requirements (build machine):

```bash
sudo apt install build-essential libssl-dev zlib1g-dev libzstd-dev
```

Then:

```bash
git clone https://github.com/celikfana-lab/anti-Anubis.git
cd anti-Anubis
./install.sh
```

`install.sh` builds a statically linked host and installs:

| what | where |
|---|---|
| host binary | `~/snap/firefox/common/anubis-native/anubis_native` |
| host manifest (regular Firefox) | `~/.mozilla/native-messaging-hosts/anubis_native.json` |
| host manifest (snap Firefox) | `~/snap/firefox/common/.mozilla/native-messaging-hosts/anubis_native.json` |

### Load the extension

Temporary (until Firefox restarts):

1. Open `about:debugging#/runtime/this-firefox`.
2. **Load Temporary Add-on…**
3. Select `manifest.json` from this repository.

Permanent: sign the add-on (unlisted AMO) or use Firefox Developer
Edition/Nightly with `xpinstall.signatures.required=false`.

### Private windows

Firefox does not run extensions in private windows by default. Go to
`about:addons` → **Anubis Native Solver** → **Details** → enable
**Run in Private Windows**.

### Snap Firefox

The host is built **statically** because snap Firefox (core24) cannot see your
system glibc/OpenSSL. `install.sh` copies it into the snap's home and writes the
snap native-messaging manifest for you.

## Build only

```bash
make -C native          # -> native/anubis_native
make -C native dynamic  # dynamic build for debugging
```

## Troubleshooting

- **Still sees `Calculating…` / the page solver runs**: make sure the add-on is
  listed in `about:debugging`, not in a private window, and check the Browser
  Console (`Ctrl+Shift+J`) for `[anubis-native]` errors.
- **`No such native application anubis_native`**: re-run `./install.sh` and
  restart Firefox. Verify the manifest contains the right `path` and
  `allowed_extensions: ["anubis-native@flixbrute.local"]`.
- **`Error: An unexpected error occurred` from the host**: inspect the Browser
  Console; the host writes diagnostics to stderr (Firefox forwards it to the
  console).
- **No `~/anubis-native.log`**: the host never ran (add-on inactive or the
  page was served from cache with a valid auth cookie). Append `?x=random` to
  the URL or clear the site's cookies.

## Security & privacy

- The native host is local; it reads framed JSON on stdin and writes JSON on
  stdout. Nothing is uploaded.
- The extension asks for `<all_urls>` only so the background can read Anubis
  challenge pages and fetch the `css-load` probe with the page's cookies. It
  does not contact any remote service.
- The host runs as your user and is launched by Firefox; no setuid, no daemon,
  no open port.
- Respect the terms of service of sites you visit and use this on systems you
  are authorized to access.

## Keywords / search terms

Anubis solver, Anubis bypass, Anubis proof-of-work solver, Anubis anti-bot,
Techaro Anubis, Firefox Anubis extension, native messaging Anubis,
Anubis difficulty 6, git.ffmpeg.org Anubis, Firefox native solver,
anti-bot challenge solver, Anubis JS/WASM replacement, Anubis hashx,
Anubis argon2id, Anubis sha256, CHIPS partitioned cookies, WebExtension
native messaging.

## Credits & license

- [Anubis](https://github.com/TecharoHQ/anubis) by Techaro (MIT) — challenge
  formats and algorithms.
- [HashX](https://github.com/tevador/hashx) by tevador / The Tor Project —
  `native/solver/hashx.c` is a C port and remains **LGPL-3.0** (see
  `LICENSES/LGPL-3.0.txt`).
- The native solver is derived from the `flixbrute` project by the same author.

Everything else is MIT — see [LICENSE](LICENSE). The bundled `hashx` source is
LGPL-3.0; the rest of the project is MIT.
