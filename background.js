"use strict";

/*
 * Native messaging + Anubis detector/blocker + main-frame response hijack.
 *
 * - onHeadersReceived spots the Anubis verification cookie (or /.within.website/)
 *   before the challenge page runs.
 * - For a detected main-frame HTML challenge, filterResponseData() buffers the
 *   original body, extracts #anubis_version / #anubis_base_prefix /
 *   #anubis_challenge, and writes a tiny HTML page instead.  The browser never
 *   loads Anubis' CSS, main.mjs, worker scripts, WASM, or mascots.
 * - The content script paints the black whale/progress screen and solves via
 *   the native host.
 * - If anything in the filter fails, the original body is passed through.
 * - If the native host fails, the tab is force-allowed, reloaded, and Anubis'
 *   page solver takes over.
 */

const HOST = "anubis_native";
const JS_PATH = "/.within.website/x/cmd/anubis/static/js/";
const PASSTHROUGH = "anubis_native_passthrough=1";

const seenHosts = new Set();
const anubisTabs = new Set();
const forceAllow = new Set();

browser.storage.local
  .get("anubisSeen")
  .then((r) => {
    for (const h of Object.keys(r.anubisSeen || {})) seenHosts.add(h);
  })
  .catch(() => {});

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch (e) {
    return "";
  }
}

function scriptTag(html, id) {
  const re = new RegExp(
    "<script[^>]*\\bid\\s*=\\s*[\"']" +
      id +
      "[\"'][^>]*>[\\s\\S]*?<\\/script>",
    "i"
  );
  const m = html.match(re);
  return m ? m[0] : "";
}

function concatChunks(chunks) {
  let n = 0;
  for (const c of chunks) n += c.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

async function decodeBody(bytes, contentEncoding) {
  /* Depending on the Firefox version, StreamFilter may hand us the decoded
     body (usually the case for text/html) or the raw encoded bytes. */
  if (bytes.length > 1 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    const stream = new Blob([bytes]).stream().pipeThrough(
      new DecompressionStream("gzip")
    );
    return await new Response(stream).text();
  }

  if (/^deflate/i.test(contentEncoding || "")) {
    for (const fmt of ["deflate", "deflate-raw"]) {
      try {
        const stream = new Blob([bytes]).stream().pipeThrough(
          new DecompressionStream(fmt)
        );
        return await new Response(stream).text();
      } catch (e) {
        /* try the next format */
      }
    }
  }

  return new TextDecoder("utf-8").decode(bytes);
}

function minimalPage(tags) {
  return (
    "<!doctype html><html><head><meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<title>Solving natively…</title></head><body>" +
    tags +
    "</body></html>"
  );
}

function escapeAttr(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;");
}

function passthroughPage(url) {
  const u = url + (url.includes("?") ? "&" : "?") + PASSTHROUGH;
  return (
    "<!doctype html><meta charset=\"utf-8\">" +
    "<meta http-equiv=\"refresh\" content=\"0;url=" +
    escapeAttr(u) +
    "\">"
  );
}

/* Keep challenge HTML uncompressed for the body filter.  This applies to
   /.within.website/ URLs and to hosts we have already seen. */
browser.webRequest.onBeforeSendHeaders.addListener(
  (d) => {
    if (d.type !== "main_frame") return;
    let u;
    try {
      u = new URL(d.url);
    } catch (e) {
      return;
    }
    if (!u.pathname.includes("/.within.website/") && !seenHosts.has(u.host))
      return;
    const headers = d.requestHeaders || [];
    const h = headers.find(
      (x) => x.name.toLowerCase() === "accept-encoding"
    );
    if (h) h.value = "identity";
    else headers.push({ name: "Accept-Encoding", value: "identity" });
    return { requestHeaders: headers };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);

/* Runs before the body/scripts; marks the tab so the blocker/HUD is active
   even on the very first visit, persists the host, and hijacks the document. */
browser.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (d.tabId < 0 || d.type !== "main_frame") return;

    const host = hostOf(d.url);
    if (!host) return;

    const headers = d.responseHeaders || [];
    const cookies = headers
      .filter((h) => h.name.toLowerCase() === "set-cookie")
      .map((h) => h.value || "")
      .join("\n");

    const isAnubis =
      /anubis-cookie-verification/i.test(cookies) ||
      d.url.includes("/.within.website/");

    if (!isAnubis) {
      anubisTabs.delete(d.tabId);
      forceAllow.delete(d.tabId);
      return;
    }

    anubisTabs.add(d.tabId);
    if (!seenHosts.has(host)) {
      seenHosts.add(host);
      browser.storage.local
        .get("anubisSeen")
        .then((r) => {
          const seen = r.anubisSeen || {};
          if (!seen[host]) {
            seen[host] = { ts: Date.now() };
            return browser.storage.local.set({ anubisSeen: seen });
          }
        })
        .catch(() => {});
    }

    /* The native fallback wants the real Anubis page + page solver. */
    if (forceAllow.has(d.tabId)) return;
    if (d.statusCode !== 200) return;
    if (d.url.includes(PASSTHROUGH)) return;

    const contentType =
      (headers.find((h) => h.name.toLowerCase() === "content-type") || {})
        .value || "";
    if (!/text\/html/i.test(contentType)) return;

    const contentEncoding =
      (headers.find((h) => h.name.toLowerCase() === "content-encoding") || {})
        .value || "";
    if (contentEncoding && !/^(identity|gzip|x-gzip|deflate)$/i.test(contentEncoding.trim()))
      return; /* br/unknown: let the normal page load */

    let filter;
    try {
      filter = browser.webRequest.filterResponseData(d.requestId);
    } catch (e) {
      return;
    }

    const chunks = [];
    filter.ondata = (event) => {
      chunks.push(new Uint8Array(event.data));
    };
    filter.onerror = () => {
      try {
        filter.close();
      } catch (e) {
        /* ignore */
      }
    };
    filter.onstop = async () => {
      let text = "";
      try {
        text = await decodeBody(concatChunks(chunks), contentEncoding);
        const chal = scriptTag(text, "anubis_challenge");
        if (!chal) throw new Error("anubis_challenge not found");
        const tags =
          scriptTag(text, "anubis_version") +
          scriptTag(text, "anubis_base_prefix") +
          chal;
        filter.write(new TextEncoder().encode(minimalPage(tags)));
      } catch (e) {
        /* Pass the decoded original through, or reload without filtering. */
        try {
          filter.write(
            new TextEncoder().encode(
              text || passthroughPage(d.url)
            )
          );
        } catch (e2) {
          /* ignore */
        }
      }
      try {
        filter.close();
      } catch (e) {
        /* ignore */
      }
    };

    const kept = headers.filter(
      (h) =>
        !/^(content-length|content-encoding|content-security-policy)$/i.test(
          h.name
        )
    );
    return { responseHeaders: kept };
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders", "blocking"]
);

browser.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (d.tabId < 0) return;
    if (d.type === "main_frame") anubisTabs.delete(d.tabId);
    if (forceAllow.has(d.tabId)) return;
    if (d.type !== "script") return;
    if (d.originUrl && d.originUrl.startsWith("moz-extension://")) return;

    let u;
    try {
      u = new URL(d.url);
    } catch (e) {
      return;
    }

    /* This path only exists on Anubis challenge pages.  Block it on the very
       first visit too; the content script + native host replace the solver. */
    if (!u.pathname.includes(JS_PATH)) return;
    return { cancel: true };
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

browser.tabs.onRemoved.addListener((id) => {
  anubisTabs.delete(id);
  forceAllow.delete(id);
});

async function rememberJS(msg, sender) {
  const host =
    msg.host ||
    (sender.tab && sender.tab.url ? hostOf(sender.tab.url) : "");
  if (!host) return { ok: false };

  /* Reuse the cached hash for the same Anubis version; don't re-download the
     challenge JS on every fresh challenge. */
  const cached = await browser.storage.local.get("anubisSeen");
  const prev = (cached.anubisSeen || {})[host];
  if (prev && prev.hash && (!msg.version || prev.version === msg.version)) {
    seenHosts.add(host);
    return { ok: true, hash: prev.hash, cached: true };
  }

  let hash = "";
  try {
    const r = await fetch(msg.mainJs, { cache: "no-store", credentials: "omit" });
    if (r.ok) {
      const text = await r.text();
      const buf = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(text)
      );
      hash = [...new Uint8Array(buf)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }
  } catch (e) {
    /* fall back to hashing the version string */
  }

  if (!hash) {
    const buf = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(
        String(msg.version || "") + "|" + String(msg.basePrefix || "")
      )
    );
    hash = [...new Uint8Array(buf)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  seenHosts.add(host);
  const r = await browser.storage.local.get("anubisSeen");
  const seen = r.anubisSeen || {};
  seen[host] = {
    hash,
    version: msg.version || null,
    basePrefix: msg.basePrefix || "",
    ts: Date.now()
  };
  await browser.storage.local.set({ anubisSeen: seen });
  return { ok: true, hash };
}

browser.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || typeof msg.type !== "string") return;

  if (msg.type === "anubis-known") {
    /* True only for the current navigation, not merely a known host: this
       avoids flashing the black overlay on normal pages of that host. */
    return Promise.resolve(
      !!(sender.tab && anubisTabs.has(sender.tab.id))
    );
  }

  if (msg.type === "anubis-fail") {
    if (sender.tab && sender.tab.id >= 0) forceAllow.add(sender.tab.id);
    return Promise.resolve({ ok: true });
  }

  if (msg.type === "anubis-seen") return rememberJS(msg, sender);

  if (msg.type !== "anubis-solve") return;

  return (async () => {
    let resp;
    try {
      resp = await browser.runtime.sendNativeMessage(HOST, {
        type: "solve",
        url: msg.url,
        challenge: msg.challenge,
        basePrefix: msg.basePrefix || ""
      });
    } catch (e) {
      return { ok: false, error: "native host: " + e };
    }

    if (!resp || !resp.ok || !resp.passUrl)
      return { ok: false, error: (resp && resp.error) || "no passUrl" };

    /* css-load extension: the server only accepts the pass request after this
       probe has been fetched.  Do it from the background (not subject to the
       page's CSP), with the page's cookies. */
    if (resp.cssUrl) {
      try {
        const r = await fetch(resp.cssUrl, {
          credentials: "include",
          cache: "no-store"
        });
        if (!r.ok)
          return { ok: false, error: "css-load probe: HTTP " + r.status };
      } catch (e) {
        return { ok: false, error: "css-load probe: " + e };
      }
    }

    return {
      ok: true,
      passUrl: resp.passUrl,
      delayMs: resp.delayMs || 0
    };
  })();
});
