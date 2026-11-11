const { onCall } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

initializeApp();

const clip = (v, n = 300) => (typeof v === "string" ? v.slice(0, n) : null);

// IP privati o locali: se finisce qui uno di questi, l'IP letto non è quello del visitatore.
const isPrivate = (ip) =>
  /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) || /^(::1$|f[cd]|fe80)/i.test(ip);

// Posizione dall'IP. Prova due servizi gratuiti; se falliscono entrambi, salva il motivo.
async function lookupGeo(ip) {
  const errors = [];
  const providers = [
    {
      name: "ipwho.is",
      url: `https://ipwho.is/${encodeURIComponent(ip)}`,
      parse: (g) => (g.success === false ? { err: g.message || "rifiutato" }
        : { city: g.city, region: g.region, country: g.country, org: (g.connection && (g.connection.isp || g.connection.org)) }),
    },
    {
      name: "ipapi.co",
      url: `https://ipapi.co/${encodeURIComponent(ip)}/json/`,
      parse: (g) => (g.error ? { err: g.reason || "rifiutato" }
        : { city: g.city, region: g.region, country: g.country_name, org: g.org }),
    },
  ];
  for (const p of providers) {
    try {
      const r = await fetch(p.url, { signal: AbortSignal.timeout(3000), headers: { "User-Agent": "zerosfx-logaccess" } });
      if (!r.ok) { errors.push(`${p.name}: HTTP ${r.status}`); continue; }
      const out = p.parse(await r.json());
      if (out.err) { errors.push(`${p.name}: ${out.err}`); continue; }
      return {
        geo: { city: out.city || null, region: out.region || null, country: out.country || null, org: out.org || null },
        source: p.name, error: null,
      };
    } catch (e) {
      errors.push(`${p.name}: ${e.name === "TimeoutError" ? "timeout" : e.message}`);
    }
  }
  return { geo: null, source: null, error: errors.join(" | ") };
}

exports.logAccess = onCall({ region: "europe-west1" }, async (request) => {
  if (!request.auth) return { ok: false };   // solo utenti autenticati

  const req = request.rawRequest;
  // Catena completa degli IP: se qualcuno prova a falsificare l'header, i valori finti stanno all'inizio;
  // l'ultimo è quello aggiunto dall'infrastruttura Google.
  const chain = String(req.headers["x-forwarded-for"] || "")
    .split(",").map((x) => x.trim()).filter(Boolean);
  const ip = chain.length ? chain[chain.length - 1] : (req.ip || null);

  let geoRes = { geo: null, source: null, error: "nessun IP" };
  if (ip && isPrivate(ip)) geoRes = { geo: null, source: null, error: `IP privato (${ip}): l'IP scelto non è quello del visitatore` };
  else if (ip) geoRes = await lookupGeo(ip);
  if (geoRes.error) console.warn("Geo non disponibile:", geoRes.error);

  const d = request.data || {};
  await getFirestore().collection("accessi").add({
    uid: request.auth.uid,
    email: request.auth.token.email || null,
    ip,
    ipChain: chain,
    geo: geoRes.geo,
    geoSource: geoRes.source,
    geoErrore: geoRes.error,
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
