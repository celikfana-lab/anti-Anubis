"use strict";

/*
 * Native messaging counterpart of content.js.
 *
 * The content script cannot talk to a native host directly, so it asks us and
 * we forward the challenge JSON to the C solver.  The host returns a
 * pass-challenge URL; the content script navigates to it (so the browser keeps
 * its own cookies/session).
 */

const HOST = "anubis_native";

browser.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.type !== "anubis-solve") return;

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
