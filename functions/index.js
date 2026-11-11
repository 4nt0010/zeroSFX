const { onCall } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

initializeApp();

const clip = (v, n = 300) => (typeof v === "string" ? v.slice(0, n) : null);

exports.logAccess = onCall({ region: "europe-west1" }, async (request) => {
  if (!request.auth) return { ok: false };   // solo utenti autenticati

  const req = request.rawRequest;
  // Catena completa degli IP: se qualcuno prova a falsificare l'header, i valori finti stanno all'inizio;
  // l'ultimo è quello aggiunto dall'infrastruttura Google.
  const chain = String(req.headers["x-forwarded-for"] || "")
    .split(",").map((x) => x.trim()).filter(Boolean);
  const ip = chain.length ? chain[chain.length - 1] : (req.ip || null);

  // Posizione approssimativa dall'IP (città/operatore). Se il servizio non risponde, si registra lo stesso.
  let geo = null;
  if (ip) {
    try {
      const r = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, { signal: AbortSignal.timeout(3000) });
      if (r.ok) {
        const g = await r.json();
        if (!g.error) geo = { city: g.city || null, region: g.region || null, country: g.country_name || null, org: g.org || null };
      }
    } catch (e) { /* niente geo */ }
  }

  const d = request.data || {};
  await getFirestore().collection("accessi").add({
    uid: request.auth.uid,
    email: request.auth.token.email || null,
    ip,
    ipChain: chain,
    geo,
    deviceToken: clip(d.deviceToken, 64),
    ua: clip(d.ua),
    lang: clip(d.lang, 32),
    tz: clip(d.tz, 64),
    screen: clip(d.screen, 32),
    platform: clip(d.platform, 64),
    at: FieldValue.serverTimestamp(),
  });
  return { ok: true };
});
