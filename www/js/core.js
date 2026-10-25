/* KOFRE web - noyau du coffre (chiffrement local), compatible avec le format v2 de la version PC.

   - Données chiffrées en AES-256-GCM avec une clé de données (DEK) aléatoire.
   - La DEK est enveloppée deux fois : par une clé dérivée du mot de passe maître (Argon2id)
     et par une clé dérivée de la clé de récupération.
   - Rien n'est envoyé nulle part : le coffre est un texte JSON chiffré, gardé dans le stockage
     de l'appareil (voir « Stockage »).
   Argon2id vient de la bibliothèque hash-wasm (globalThis.hashwasm), fournie localement. */

export const VERSION = 2;
export const KDF_PARAMS = { time_cost: 3, memory_cost: 65536, parallelism: 4 }; // 64 Mo
export const DUREE_CORBEILLE = 30 * 24 * 3600;
const CTX_MDP = "KOFRE-enveloppe-mdp";
const CTX_RECUP = "KOFRE-enveloppe-recup";
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

export class CoffreError extends Error {}
export class MotDePasseIncorrect extends CoffreError {}
export class CleRecuperationIncorrecte extends CoffreError {}
export class CoffreVerrouille extends CoffreError {}

const subtle = () => globalThis.crypto.subtle;
const octetsAleatoires = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
const maintenant = () => Math.floor(Date.now() / 1000);
// Heure réelle (et non un compteur qui s'arrête quand le téléphone dort) : une veille compte comme de l'inactivité.
const horloge = () => Date.now() / 1000;

export function b64e(octets) {
  let s = "";
  for (let i = 0; i < octets.length; i += 0x8000) s += String.fromCharCode(...octets.subarray(i, i + 0x8000));
  return btoa(s);
}
export function b64d(texte) {
  if (typeof texte !== "string") throw new TypeError("base64 attendu");
  const s = atob(texte);
  const o = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i);
  return o;
}

async function deriverCle(motDePasse, sel, params) {
  const h = globalThis.hashwasm;
  if (!h) throw new CoffreError("Module de chiffrement indisponible.");
  return h.argon2id({
    password: enc.encode(motDePasse),
    salt: sel,
    parallelism: params.parallelism,
    iterations: params.time_cost,
    memorySize: params.memory_cost,
    hashLength: 32,
    outputType: "binary",
  });
}

async function aesChiffrer(cle, nonce, clair, ad) {
  const k = await subtle().importKey("raw", cle, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce, additionalData: ad }, k, clair));
}
async function aesDechiffrer(cle, nonce, chiffre, ad) {
  const k = await subtle().importKey("raw", cle, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: nonce, additionalData: ad }, k, chiffre));
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export function base32Encoder(octets) {
  let bits = 0, val = 0, s = "";
  for (const o of octets) {
    val = (val << 8) | o; bits += 8;
    while (bits >= 5) { s += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) s += B32[(val << (5 - bits)) & 31];
  return s;
}

function genererCleRecuperation() {
  const brut = base32Encoder(octetsAleatoires(20)); // 32 caractères
  return brut.match(/.{4}/g).join("-");
}
export function normaliserCle(cle) {
  return (cle || "").toUpperCase().replace(/[^\p{L}\p{N}]/gu, "");
}

async function envelopper(kek, dek, contexte) {
  const nonce = octetsAleatoires(12);
  return { nonce: b64e(nonce), cle: b64e(await aesChiffrer(kek, nonce, dek, enc.encode(contexte))) };
}
async function deballer(kek, enveloppe, contexte) {
  return aesDechiffrer(kek, b64d(enveloppe.nonce), b64d(enveloppe.cle), enc.encode(contexte));
}

function verifierParams(p) {
  const cles = ["time_cost", "memory_cost", "parallelism"];
  const ok = p && typeof p === "object" && cles.every((k) => Number.isInteger(p[k])) &&
    p.time_cost >= 1 && p.time_cost <= 20 && p.parallelism >= 1 && p.parallelism <= 16 &&
    p.memory_cost >= 8 * p.parallelism && p.memory_cost <= 262144;
  if (!ok) throw new CoffreError("Paramètres de chiffrement invalides : fichier refusé.");
}

function lireJson(texte) {
  try {
    const d = JSON.parse(texte);
    if (!d || typeof d !== "object" || Array.isArray(d)) throw new Error("format");
    return d;
  } catch {
    throw new CoffreError("Fichier de coffre illisible.");
  }
}

function entete(version) { return enc.encode("KOFRE-v" + version); }

/* ---------- générateurs ---------- */
function entierAleatoire(n) { // sans biais (rejet)
  const limite = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    globalThis.crypto.getRandomValues(buf);
    if (buf[0] < limite) return buf[0] % n;
  }
}
const choisir = (alphabet) => alphabet[entierAleatoire(alphabet.length)];

export function genererMotDePasse(longueur = 18, majuscules = true, chiffres = true, symboles = true) {
  if (!(longueur >= 8)) throw new RangeError("La longueur minimale est de 8 caractères.");
  const groupes = ["abcdefghijklmnopqrstuvwxyz"];
  if (majuscules) groupes.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  if (chiffres) groupes.push("0123456789");
  if (symboles) groupes.push("!@#$%^&*-_+=?");
  const alphabet = groupes.join("");
  for (;;) {
    let mdp = "";
    for (let i = 0; i < longueur; i++) mdp += choisir(alphabet);
    if (groupes.every((g) => [...mdp].some((c) => g.includes(c)))) return mdp;
  }
}
export function genererMotDePasseMaitre() {
  const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  return [0, 1, 2, 3].map(() => [0, 1, 2, 3].map(() => choisir(alphabet)).join("")).join("-");
}

function nouvelId() {
  if (globalThis.crypto.randomUUID) return globalThis.crypto.randomUUID().replace(/-/g, "");
  return [...octetsAleatoires(16)].map((o) => o.toString(16).padStart(2, "0")).join("");
}

/* ---------- stockage ---------- */
/** Stockage du texte du coffre. Par défaut : localStorage ; remplaçable (ex. fichier sous Android). */
export class Stockage {
  constructor(cle = "kofre.coffre", magasin = globalThis.localStorage) { this.cle = cle; this.m = magasin; }
  existe() { return this.m.getItem(this.cle) !== null; }
  lire() { const t = this.m.getItem(this.cle); if (t === null) throw new CoffreError("Fichier de coffre illisible."); return t; }
  ecrire(texte) { this.m.setItem(this.cle, texte); }
  copierVers(nom) { this.m.setItem(nom, this.lire()); }
}

/* ---------- coffre ---------- */
export class Coffre {
  constructor(stockage, delai = 300) {
    this.stockage = stockage;
    this.delai = delai; // secondes d'inactivité
    this._dek = null; this._sel = null; this._params = null;
    this._envMdp = null; this._envRecup = null;
    this._entrees = [];
    this._derniere = 0;
    this.cleRecuperation = null; // renseignée une seule fois, à afficher puis remettre à null
  }

  static async creer(stockage, motDePasse, delai = 300) {
    if (stockage.existe()) throw new CoffreError("Un coffre existe déjà à cet emplacement.");
    if ([...motDePasse].length < 12) throw new CoffreError("Le mot de passe maître doit faire au moins 12 caractères.");
    const c = new Coffre(stockage, delai);
    c._params = { ...KDF_PARAMS };
    c._dek = octetsAleatoires(32);
    await c._definirMotDePasse(motDePasse);
    c.cleRecuperation = await c._nouvelleCleRecuperation();
    c._toucher();
    await c._sauvegarder();
    return c;
  }

  static async ouvrir(stockage, motDePasse, delai = 300) {
    const data = lireJson(stockage.lire());
    const c = new Coffre(stockage, delai);
    try {
      const version = data.version === undefined ? 1 : data.version;
      if (version === 1) throw new CoffreError("Ancien format de coffre : ouvrez-le d'abord avec la version PC de KOFRE (mise à jour automatique).");
      if (version !== 2) throw new CoffreError("Version de coffre non prise en charge.");
      c._sel = b64d(data.sel);
      c._params = data.kdf;
      verifierParams(c._params);
      const kek = await deriverCle(motDePasse, c._sel, c._params);
      try { c._dek = await deballer(kek, data.mdp, CTX_MDP); }
      catch { throw new MotDePasseIncorrect("Mot de passe incorrect ou coffre modifié."); }
      c._envMdp = data.mdp;
      c._envRecup = data.recup;
      c._entrees = await c._dechiffrerEntrees(data);
    } catch (e) {
      if (e instanceof CoffreError) throw e;
      throw new CoffreError("Fichier de coffre invalide.");
    }
    c._toucher();
    if (c._purgerCorbeille()) await c._sauvegarder();
    return c;
  }

  /** « Mot de passe oublié » : la clé de récupération permet de choisir un nouveau mot de passe maître. */
  static async recuperer(stockage, cle, nouveauMotDePasse, delai = 300) {
    if ([...nouveauMotDePasse].length < 12) throw new CoffreError("Le mot de passe maître doit faire au moins 12 caractères.");
    const norm = normaliserCle(cle);
    if (norm.length !== 32) throw new CleRecuperationIncorrecte("Clé de récupération incorrecte (32 caractères attendus).");
    const data = lireJson(stockage.lire());
    if (data.version !== 2) throw new CoffreError("Ce coffre n'a pas encore de clé de récupération : ouvrez-le d'abord avec votre mot de passe maître.");
    const c = new Coffre(stockage, delai);
    try {
      c._params = data.kdf;
      verifierParams(c._params);
      const env = data.recup;
      const kek = await deriverCle(norm, b64d(env.sel), c._params);
      try { c._dek = await deballer(kek, env, CTX_RECUP); }
      catch { throw new CleRecuperationIncorrecte("Clé de récupération incorrecte."); }
      c._entrees = await c._dechiffrerEntrees(data);
    } catch (e) {
      if (e instanceof CoffreError) throw e;
      throw new CoffreError("Fichier de coffre invalide.");
    }
    await c._definirMotDePasse(nouveauMotDePasse);
    c.cleRecuperation = await c._nouvelleCleRecuperation();
    c._toucher();
    await c._sauvegarder();
    return c;
  }

  /** Remplace le coffre par une sauvegarde (texte), après avoir vérifié qu'elle s'ouvre avec ce mot de passe.
      L'ancien coffre est gardé sous un autre nom dans le stockage. Retourne le coffre ouvert. */
  static async restaurer(texteSauvegarde, motDePasse, stockage, delai = 300) {
    const data = lireJson(texteSauvegarde);
    if (data.version !== 2) throw new CoffreError("Ce fichier n'est pas une sauvegarde KOFRE valide.");
    const temp = new Stockage("kofre.verification", { // stockage jetable en mémoire : la sauvegarde n'est pas modifiée
      _v: texteSauvegarde, getItem() { return this._v; }, setItem(_, t) { this._v = t; },
    });
    const verifie = await Coffre.ouvrir(temp, motDePasse, delai); // MotDePasseIncorrect si faux
    verifie.verrouiller();
    if (stockage.existe()) {
      const d = new Date(), p = (n) => String(n).padStart(2, "0");
      stockage.copierVers(`kofre.avant-restauration-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`);
    }
    stockage.ecrire(texteSauvegarde);
    return Coffre.ouvrir(stockage, motDePasse, delai);
  }

  /* ----- clés ----- */
  async _definirMotDePasse(motDePasse) {
    this._sel = octetsAleatoires(16);
    const kek = await deriverCle(motDePasse, this._sel, this._params);
    this._envMdp = await envelopper(kek, this._dek, CTX_MDP);
  }
  async _nouvelleCleRecuperation() {
    const cle = genererCleRecuperation();
    const sel = octetsAleatoires(16);
    const kek = await deriverCle(normaliserCle(cle), sel, this._params);
    this._envRecup = { sel: b64e(sel), ...(await envelopper(kek, this._dek, CTX_RECUP)) };
    return cle;
  }
  async _dechiffrerEntrees(data) {
    let clair;
    try { clair = await aesDechiffrer(this._dek, b64d(data.nonce), b64d(data.donnees), entete(data.version)); }
    catch { throw new CoffreError("Le coffre est modifié ou corrompu."); }
    const liste = JSON.parse(dec.decode(clair));
    if (!Array.isArray(liste)) throw new CoffreError("Fichier de coffre invalide.");
    return liste;
  }

  /* ----- verrouillage ----- */
  _toucher() { this._derniere = horloge(); }
  _verifier(activite = true) {
    if (this._dek === null) throw new CoffreVerrouille("Le coffre est verrouillé.");
    const ecart = horloge() - this._derniere;
    if (ecart > this.delai || ecart < 0) { // ecart < 0 : l'heure de l'appareil a été reculée
      this.verrouiller();
      throw new CoffreVerrouille("Verrouillé automatiquement après inactivité.");
    }
    if (activite) this._toucher();
  }
  verrouiller() {
    if (this._dek) this._dek.fill(0);
    this._dek = null; this._entrees = []; this._envMdp = this._envRecup = null;
  }
  get estVerrouille() { return this._dek === null; }

  /* ----- entrées ----- */
  async ajouter(nom, identifiant, motDePasse, categorie = "Autre", notes = "", site = "", favori = false, totp = "") {
    this._verifier();
    const t = maintenant();
    const e = { id: nouvelId(), nom, identifiant, mot_de_passe: motDePasse, categorie, notes, site,
      favori: !!favori, totp, cree: t, modifie: t };
    this._entrees.push(e);
    await this._sauvegarder();
    return e.id;
  }
  async ajouterPlusieurs(liste) {
    this._verifier();
    const t = maintenant();
    let n = 0;
    for (const d of liste) {
      this._entrees.push({ id: nouvelId(), nom: d.nom, identifiant: d.identifiant || "", mot_de_passe: d.mot_de_passe,
        categorie: d.categorie || "Autre", notes: d.notes || "", site: d.site || "", favori: !!d.favori,
        totp: d.totp || "", cree: t, modifie: t });
      n++;
    }
    if (n) await this._sauvegarder();
    return n;
  }
  _vivantes() { return this._entrees.filter((e) => !e.supprime); }
  lister() {
    this._verifier();
    return this._vivantes().map((e) => ({ id: e.id, nom: e.nom, identifiant: e.identifiant, categorie: e.categorie,
      modifie: e.modifie, favori: !!e.favori }));
  }
  obtenir(id, activite = true) {
    this._verifier(activite);
    const e = this._vivantes().find((x) => x.id === id);
    if (!e) throw new CoffreError("Entrée introuvable.");
    return { site: "", favori: false, totp: "", ...e };
  }
  async modifier(id, champs) {
    this._verifier();
    const autorises = ["nom", "identifiant", "mot_de_passe", "categorie", "notes", "site", "favori", "totp"];
    const e = this._vivantes().find((x) => x.id === id);
    if (!e) throw new CoffreError("Entrée introuvable.");
    for (const [k, v] of Object.entries(champs)) {
      if (!autorises.includes(k)) throw new CoffreError("Champ non modifiable : " + k);
      e[k] = v;
    }
    if (Object.keys(champs).some((k) => k !== "favori")) e.modifie = maintenant();
    await this._sauvegarder();
  }

  /* ----- corbeille ----- */
  async supprimer(id) {
    this._verifier();
    const e = this._vivantes().find((x) => x.id === id);
    if (!e) throw new CoffreError("Entrée introuvable.");
    e.supprime = maintenant();
    await this._sauvegarder();
  }
  _purgerCorbeille() {
    const limite = maintenant() - DUREE_CORBEILLE;
    const avant = this._entrees.length;
    this._entrees = this._entrees.filter((e) => !(e.supprime && e.supprime < limite));
    return this._entrees.length !== avant;
  }
  async listerCorbeille() {
    this._verifier();
    if (this._purgerCorbeille()) await this._sauvegarder();
    return this._entrees.filter((e) => e.supprime).sort((a, b) => b.supprime - a.supprime).map((e) => ({
      id: e.id, nom: e.nom, identifiant: e.identifiant, categorie: e.categorie, supprime: e.supprime,
      reste: Math.max(0, Math.ceil((e.supprime + DUREE_CORBEILLE - maintenant()) / 86400)),
    }));
  }
  _aLaCorbeille(id) {
    const e = this._entrees.find((x) => x.id === id && x.supprime);
    if (!e) throw new CoffreError("Entrée introuvable dans la corbeille.");
    return e;
  }
  async restaurerEntree(id) { this._verifier(); delete this._aLaCorbeille(id).supprime; await this._sauvegarder(); }
  async supprimerDefinitivement(id) {
    this._verifier();
    const e = this._aLaCorbeille(id);
    this._entrees = this._entrees.filter((x) => x !== e);
    await this._sauvegarder();
  }
  async viderCorbeille() {
    this._verifier();
    const avant = this._entrees.length;
    this._entrees = this._vivantes();
    await this._sauvegarder();
    return avant - this._entrees.length;
  }

  /* ----- sécurité du coffre ----- */
  async changerMotDePasseMaitre(nouveau) {
    this._verifier();
    if ([...nouveau].length < 12) throw new CoffreError("Le mot de passe maître doit faire au moins 12 caractères.");
    await this._definirMotDePasse(nouveau);
    await this._sauvegarder();
  }
  async regenererCleRecuperation() {
    this._verifier();
    const cle = await this._nouvelleCleRecuperation();
    await this._sauvegarder();
    return cle;
  }

  /** Texte chiffré du coffre (pour une sauvegarde). */
  exporterTexte() { this._verifier(); return this.stockage.lire(); }

  async _sauvegarder() {
    const nonce = octetsAleatoires(12); // nouveau nonce à CHAQUE sauvegarde
    const clair = enc.encode(JSON.stringify(this._entrees));
    const chiffre = await aesChiffrer(this._dek, nonce, clair, entete(VERSION));
    this.stockage.ecrire(JSON.stringify({
      version: VERSION, kdf: this._params, sel: b64e(this._sel), mdp: this._envMdp, recup: this._envRecup,
      nonce: b64e(nonce), donnees: b64e(chiffre),
    }));
  }
}
