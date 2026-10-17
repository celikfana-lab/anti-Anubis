"use strict";

/*
 * Runs at document_start on http(s) pages.
 *
 * Anubis' JS/WASM solver is blocked by background.js once the challenge is
 * detected.  This script masks the page with a black "solving natively" screen
 * (whale + progress bar), sends the challenge JSON to the native host, and
 * navigates to the pass URL.
 *
 * If the native host fails, the tab is force-allowed by the background, this
 * script reloads without suppressing anything, and Anubis' own solver runs.
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

  /* ------------------------------------------------------------------ */
  /* Black overlay: whale + progress bar + message                       */
  /* ------------------------------------------------------------------ */
  let hud = null;
  let hideStyle = null;
  let uiArmed = false;

  function armUI() {
    if (uiArmed || failed) return;
    uiArmed = true;
    try {
      hideStyle = document.createElement("style");
      hideStyle.id = "__anubis_native_hide";
      hideStyle.textContent = `
        html,body{background:#000!important;margin:0!important}
        body>*:not(#__anubis_native_hud){visibility:hidden!important}
        #__anubis_native_hud{
          visibility:visible!important;position:fixed;inset:0;z-index:2147483647;
          display:flex;flex-direction:column;align-items:center;justify-content:center;
          gap:22px;background:#000;color:#fff;text-align:center;padding:24px;
          box-sizing:border-box;font:16px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;
        }
        #__anubis_native_hud img{
          width:min(220px,46vw);height:auto;
          filter:drop-shadow(0 0 32px rgba(77,107,254,.45));
        }
        #__anubis_native_hud .msg{font-size:18px;max-width:34em}
        #__anubis_native_hud .track{
          width:min(420px,72vw);height:10px;border-radius:999px;background:#15161c;
          overflow:hidden;box-shadow:inset 0 0 0 1px #262838;
        }
        #__anubis_native_hud .fill{
          width:100%;height:100%;border-radius:999px;
          transform-origin:left center;
          background:linear-gradient(90deg,#3b5bff,#7f8dff);
          animation:__anubis_native_fill 1.35s ease-in-out infinite;
        }
        @keyframes __anubis_native_fill{
          0%{transform:scaleX(.12);opacity:.65}
          50%{transform:scaleX(.92);opacity:1}
          100%{transform:scaleX(.12);opacity:.65}
        }
      `;
      (document.head || document.documentElement).appendChild(hideStyle);

      try {
        document.title = "Solving natively…";
      } catch (e) {
        /* ignore */
      }

      hud = document.createElement("div");
      hud.id = "__anubis_native_hud";

      const img = document.createElement("img");
      img.src = browser.runtime.getURL("asset/whale.webp");
      img.alt = "";

      const msg = document.createElement("div");
      msg.className = "msg";
      msg.textContent =
        "Please wait, solving natively so you save time!";

      const track = document.createElement("div");
      track.className = "track";
      const fill = document.createElement("div");
      fill.className = "fill";
      track.appendChild(fill);

      hud.append(img, msg, track);
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

  /* For repeat visits, the background knows this navigation is an Anubis
     challenge before the body parses, so the black page is up immediately.
     The marker observer below covers the first visit. */
  if (!failed) {
    browser.runtime
      .sendMessage({ type: "anubis-known", host: location.host })
      .then((known) => {
        if (known) armUI();
      })
      .catch(() => {});

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
    if (pageWin) {
      try {
        pageWin.__anubisBooted = false;
      } catch (e) {
        /* ignore */
      }
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
    /* Native path already failed once: let Anubis' page solver run. */
    if (failed) return;

    const el = document.getElementById("anubis_challenge");
    if (!el) {
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

    let version = "";
    const vel = document.getElementById("anubis_version");
    if (vel) {
      try {
        version = JSON.parse(vel.textContent);
      } catch (e) {
        version = vel.textContent.trim();
      }
    }

    /* Tell the background to fetch + SHA-256 the challenge JS and remember it
       for this host. */
    let mainJs = "";
    const script = [...document.getElementsByTagName("script")].find((s) =>
      (s.src || "").includes("/static/js/main.mjs")
    );
    if (script) mainJs = script.src;
    if (!mainJs) {
      mainJs =
        location.origin +
        (base || "") +
        "/.within.website/x/cmd/anubis/static/js/main.mjs?cacheBuster=" +
        encodeURIComponent(String(version || ""));
    }
    browser.runtime
      .sendMessage({
        type: "anubis-seen",
        host: location.host,
        version: String(version || ""),
        basePrefix: base,
        mainJs
      })
      .catch(() => {});

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
        const done = () => {
          release();
          location.reload();
        };
        /* Clear the webRequest block for this tab before reloading. */
        browser.runtime
          .sendMessage({ type: "anubis-fail" })
          .then(done, done);
      });
  }

  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();
