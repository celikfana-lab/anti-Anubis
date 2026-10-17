"use strict";

/*
 * Runs at document_start on every http(s) page.
 *
 * Anubis' own main.mjs bails out when window.__anubisBooted is already true,
 * so we set it early to stop the browser from spawning its 8 JS/WASM workers.
 * If this is not an Anubis page (or the helper fails) we release the flag (or
 * reload without suppressing) and let the normal page solver work.
 */

(() => {
  const FAIL_KEY = "__anubis_native_failed";

  let failed = false;
  try {
    failed = sessionStorage.getItem(FAIL_KEY) === "1";
  } catch (e) {
    /* sandboxed origin */
  }

  const pageWin = window.wrappedJSObject;
  if (!failed && pageWin) {
    try {
      pageWin.__anubisBooted = true;
    } catch (e) {
      /* ignore */
    }
  }

  /*
   * Mask Anubis' own challenge UI as soon as its marker element is parsed.
   * Otherwise the page paints "Calculating..." (or its localized equivalent)
   * for a frame or two before our status text appears, which looks like the
   * JS solver ran first.
   */
  let hud = null;
  let hideStyle = null;
  let uiArmed = false;

  function armUI() {
    if (uiArmed || failed) return;
    uiArmed = true;
    try {
      hideStyle = document.createElement("style");
      hideStyle.id = "__anubis_native_hide";
      hideStyle.textContent =
        "html,body{background:#1a1a1a!important}" +
        "body>*:not(#__anubis_native_hud){visibility:hidden!important}" +
        "#__anubis_native_hud{visibility:visible!important}";
      (document.head || document.documentElement).appendChild(hideStyle);

      hud = document.createElement("div");
      hud.id = "__anubis_native_hud";
      hud.textContent = "Solving natively…";
      hud.style.cssText =
        "position:fixed;inset:0;z-index:2147483647;display:flex;" +
        "align-items:center;justify-content:center;background:#1a1a1a;" +
        "color:#ddd;font:16px system-ui,sans-serif;";
      (document.body || document.documentElement).appendChild(hud);
    } catch (e) {
      /* ignore */
    }
  }

  function disarmUI() {
    try {
      if (hud && hud.parentNode) hud.parentNode.removeChild(hud);
      if (hideStyle && hideStyle.parentNode)
        hideStyle.parentNode.removeChild(hideStyle);
    } catch (e) {
      /* ignore */
    }
    hud = null;
    hideStyle = null;
    uiArmed = false;
  }

  if (!failed) {
    const probe = () =>
      document.getElementById("anubis_version") ||
      document.getElementById("anubis_challenge");
    if (probe()) armUI();
    try {
      const mo = new MutationObserver(() => {
        if (probe()) {
          armUI();
          mo.disconnect();
        }
      });
      mo.observe(document.documentElement, { childList: true, subtree: true });
    } catch (e) {
      /* ignore */
    }
  }

  const release = () => {
    if (!pageWin) return;
    try {
      pageWin.__anubisBooted = false;
    } catch (e) {
      /* ignore */
    }
    disarmUI();
  };

  /*
   * Navigate from the page's own principal, not the content-script sandbox.
   * This matters for Partitioned (CHIPS) cookies: the pass-challenge request
   * must look like a first-party top-level navigation to the site.
   */
  function navigate(url) {
    let injected = false;
    try {
      const s = document.createElement("script");
      s.textContent =
        "window.__anubisNativeNavigating=true;location.replace(" +
        JSON.stringify(url) +
        ");";
      (document.head || document.documentElement).appendChild(s);
      s.remove();
      injected = true;
    } catch (e) {
      injected = false;
    }

    /* If a CSP blocked the inline script, fall back to the normal navigation. */
    setTimeout(() => {
      let started = false;
      try {
        started = !!(pageWin && pageWin.__anubisNativeNavigating);
      } catch (e) {
        started = false;
      }
      if (!started) location.replace(url);
    }, 800);

    if (!injected) location.replace(url);
  }

  function start() {
    const el = document.getElementById("anubis_challenge");
    if (!el) {
      /* Not an Anubis challenge.  Undo the suppression and clear any fallback. */
      release();
      try {
        sessionStorage.removeItem(FAIL_KEY);
      } catch (e) {
        /* ignore */
      }
      return;
    }

    let base = "";
    const bel = document.getElementById("anubis_base_prefix");
    if (bel) {
      try {
        base = JSON.parse(bel.textContent) || "";
      } catch (e) {
        /* ignore */
      }
    }

    const status = document.getElementById("status");
    if (status) status.textContent = "Solving natively…";

    browser.runtime
      .sendMessage({
        type: "anubis-solve",
        url: location.href,
        challenge: el.textContent,
        basePrefix: base
      })
      .then((resp) => {
        if (!resp || !resp.ok || !resp.passUrl)
          throw new Error((resp && resp.error) || "native solve failed");
        const go = () => navigate(resp.passUrl);
        if (resp.delayMs > 0) setTimeout(go, resp.delayMs);
        else go();
      })
      .catch((err) => {
        console.error("[anubis-native]", err);
        try {
          sessionStorage.setItem(FAIL_KEY, "1");
        } catch (e) {
          /* ignore */
        }
        release();
        location.reload();
      });
  }

  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();
