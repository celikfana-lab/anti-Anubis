"use strict";

/*
 * Native messaging + Anubis detector/blocker.
 *
 * - onHeadersReceived spots the Anubis verification cookie (or /.within.website/)
 *   before the challenge page body runs and remembers the host.
 * - onBeforeRequest cancels Anubis' main.mjs / worker scripts so the page's
 *   JS/WASM solver never starts.  This is what makes repeated visits instant.
 * - The challenge JS is fetched once from the background and SHA-256 hashed;
 *   the host->hash map is stored in browser.storage.local.
 * - If the native host fails, the tab is force-allowed, the content script
 *   reloads, and Anubis' normal page solver takes over.
 */

const HOST = "anubis_native";
const JS_PATH = "/.within.website/x/cmd/anubis/static/js/";

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

/* Runs before the body/scripts; marks the tab so the blocker is active even on
   the very first visit, and persists the host for later visits. */
browser.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (d.tabId < 0 || d.type !== "main_frame") return;
    const host = hostOf(d.url);
    if (!host) return;

    const cookies = (d.responseHeaders || [])
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
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
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
       first visit too; the content script + native host replace the page
       solver.  A failure sets forceAllow for the tab and reloads. */
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
