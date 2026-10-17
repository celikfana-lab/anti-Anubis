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

Two sets of measurements:

1. **Real world** — live `https://git.ffmpeg.org/ffmpeg.git` (Anubis v1.28.1, `fast` difficulty 6).
2. **Every Anubis tier** — a local Anubis v1.28.1 instance (same version as the `anubis/` checkout) using the default policy tiers and the algorithm-equivalent difficulties from the Anubis docs.

Three columns in both tables:

- **Native C (no browser)** — the C host/harness solves and passes directly; no Firefox.
- **Standard Firefox** — Firefox 157 headless with no extension; Anubis' own JS/WASM solver runs.
- **Firefox + module** — the same Firefox with this extension + native messaging.

### Real world: `git.ffmpeg.org/ffmpeg.git` (`fast` d6)

| Mode | End-to-end from process launch | Solver |
|---|---:|---:|
| Native C (no browser) | **1.00 s** | **0.30 s** |
| Standard Firefox | 30.84 s | page JS/WASM |
| Firefox + module | **7.41 s** (includes ~6 s web-ext startup) | **0.14 s** |

The module's end-to-end number is inflated by launching a fresh Firefox +
`web-ext` for every test. In an already-open Firefox the extension's own cost is
the host solve (**~0.1–0.9 s**) plus the challenge page load.

### Default policy tiers (local Anubis v1.28.1)

| Tier | Challenge | Native C (no browser) | Standard Firefox | Firefox + module |
|---|---|---:|---:|---:|
| T0 minimal | ALLOW | no challenge | no challenge | no challenge |
| T1 mild | `metarefresh` d1 | 1.11 s | 2.31 s | 2.19 s |
| T2 moderate | `fast` d2 | **7.6 ms** | 814 ms | 857 ms |
| T3 elevated | `fast` d4 | **8.0 ms** | 2.55 s | 921 ms |
| T4 extreme | `fast` d6 | **76 ms** | 13.58 s | 2.05 s |

### Algorithm-equivalent tiers

| Algorithm | Difficulty | Native C (no browser) | Standard Firefox | Firefox + module |
|---|---:|---:|---:|---:|
| `fast` | 2 | 7.6 ms | 814 ms | 857 ms |
| `fast` | 4 | 8.0 ms | 2.55 s | 921 ms |
| `fast` | 6 | 76 ms | 13.58 s | 2.05 s |
| `sha256` | 8 | 6.6 ms | 876 ms | 782 ms |
| `sha256` | 16 | 8.8 ms | 834 ms | 822 ms |
| `sha256` | 24 | 360 ms | 2.58 s | 3.41 s |
| `argon2id` | 2 | 401 ms | 1.14 s | 2.00 s |
| `argon2id` | 4 | 473 ms | 1.16 s | 1.49 s |
| `argon2id` | 6 | 500 ms | 2.06 s | 1.30 s |
| `hashx` | 7 | 11.7 ms | 860 ms | 835 ms |
| `hashx` | 15 | 15.5 ms | 966 ms | 833 ms |
| `hashx` | 20 | 445 ms | 1.30 s | 1.21 s |

**How these were measured**

- Local: Anubis v1.28.1 (same version as the `anubis/` checkout), local HTTP, i7-1260P (16 threads), 8 solver threads, 16 GB RAM.
- Challenge latency = server `new challenge issued` → `challenge accepted`. Native cells are medians of 3 runs; module cells 1; standard Firefox cells 1. Browser cells include challenge page load and JS/WASM startup.
- The module's low-tier times are dominated by the ~0.8 s challenge page/extension load. Its advantage grows with the challenge cost.
- At `fast` d6, `argon2id` d6, and on the real-world site the native path wins clearly. For cheap `sha256`/`hashx` tiers the page's WASM solver is competitive, and a single module sample can be slower than Firefox (`sha256` 24, `argon2id` 2) due to page-load and CPU variance.
- Variance is nonce- and CPU-load-dependent; browser cells are intentionally 1 run (high tiers take seconds to minutes).

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
