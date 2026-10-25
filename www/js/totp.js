/* KOFRE web - codes 2FA à usage unique (TOTP, RFC 6238), calculés localement.
   Accepte la clé secrète (base32) ou le lien complet « otpauth://totp/... ». */

export class ValueError extends Error {}
const ALGOS = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };
const MSG_SECRET = "Clé 2FA invalide : elle ne doit contenir que des lettres A-Z et des chiffres 2-7.";
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function decoderSecret(secret) {
  const s = secret.replace(/\s+/g, "").replace(/-/g, "").toUpperCase().replace(/=+$/, "");
  if (!s) throw new ValueError("Clé 2FA vide.");
  if (!/^[A-Z2-7]+$/.test(s) || [1, 3, 6].includes(s.length % 8)) throw new ValueError(MSG_SECRET);
  if (s.length < 16) throw new ValueError("Clé 2FA trop courte : copiez la clé complète donnée par le site.");
  const out = [];
  let bits = 0, val = 0;
  for (const c of s) {
    val = (val << 5) | B32.indexOf(c); bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

export function analyser(valeur) {
  const v = (valeur || "").trim();
  if (!v) throw new ValueError("Clé 2FA vide.");
  const p = { digits: 6, period: 30, algo: "SHA1" };
  let secret = v;
  if (v.toLowerCase().startsWith("otpauth://")) {
    const m = /^otpauth:\/\/([^/?#]*)[^?#]*\??([^#]*)/i.exec(v);
    if (!m || m[1].toLowerCase() !== "totp") throw new ValueError("Seuls les liens otpauth://totp/... sont pris en charge.");
    const q = new URLSearchParams(m[2]);
    if (!q.has("secret")) throw new ValueError("Le lien 2FA ne contient pas de clé secrète.");
    secret = q.get("secret");
    const num = (k, d) => {
      const t = q.has(k) ? q.get(k).trim() : String(d);
      if (!/^[+-]?\d+$/.test(t)) throw new ValueError("Paramètres 2FA invalides (chiffres ou période).");
      return parseInt(t, 10);
    };
    p.digits = num("digits", 6);
    p.period = num("period", 30);
    p.algo = (q.get("algorithm") || "SHA1").toUpperCase();
    if (!(p.algo in ALGOS) || ![6, 7, 8].includes(p.digits) || !(p.period >= 1 && p.period <= 300))
      throw new ValueError("Paramètres 2FA non pris en charge.");
  }
  p.secret = decoderSecret(secret);
  return p;
}

export function normaliser(valeur) {
  const v = (valeur || "").trim();
  analyser(v);
  if (v.toLowerCase().startsWith("otpauth://")) return v;
  return v.replace(/\s+/g, "").replace(/-/g, "").toUpperCase();
}

export async function code(valeur, maintenant) {
  const p = analyser(valeur);
  const t = maintenant === undefined ? Date.now() / 1000 : maintenant;
  const compteur = Math.floor(t / p.period);
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setUint32(0, Math.floor(compteur / 0x100000000));
  dv.setUint32(4, compteur >>> 0);
  const cle = await crypto.subtle.importKey("raw", p.secret, { name: "HMAC", hash: ALGOS[p.algo] }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", cle, buf));
  const deb = mac[mac.length - 1] & 0x0f;
  const n = (((mac[deb] & 0x7f) << 24) | (mac[deb + 1] << 16) | (mac[deb + 2] << 8) | mac[deb + 3]) % (10 ** p.digits);
  return { code: String(n).padStart(p.digits, "0"), reste: p.period - Math.floor(t % p.period), periode: p.period };
}
