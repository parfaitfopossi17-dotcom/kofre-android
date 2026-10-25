/* KOFRE web - reproduit l'API de la version PC (window.pywebview.api) au-dessus du noyau JS,
   pour que la même interface (index.html) fonctionne dans un navigateur ou une application Android. */
import {
  Coffre, CoffreError, CoffreVerrouille, MotDePasseIncorrect, CleRecuperationIncorrecte, Stockage,
  genererMotDePasse, genererMotDePasseMaitre,
} from "./core.js";
import { force, analyser } from "./analyse.js";
import * as totp from "./totp.js";
import { ValueError } from "./totp.js";
import { lireCsv } from "./importer.js";

export class FuiteErreur extends Error {}

export const DELAI_VERROUILLAGE = 300;
export const THEMES = ["sombre", "clair", "nuit"];

/* ---------- vérification de fuites (seule fonction qui utilise internet, sur clic) ---------- */
export async function motDePasseCompromis(motDePasse, appelFetch = globalThis.fetch) {
  if (!motDePasse) throw new FuiteErreur("Le mot de passe est vide.");
  const h = new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode(motDePasse)));
  const empreinte = [...h].map((o) => o.toString(16).padStart(2, "0")).join("").toUpperCase();
  const prefixe = empreinte.slice(0, 5), suffixe = empreinte.slice(5);
  let texte;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 10000);
    try {
      const r = await appelFetch("https://api.pwnedpasswords.com/range/" + prefixe, { signal: ctrl.signal });
      if (!r.ok) throw new Error("http");
      texte = await r.text();
    } finally { clearTimeout(t); }
  } catch (e) {
    throw new FuiteErreur(e instanceof TypeError || e.name === "AbortError"
      ? "Impossible de joindre le service : vérifiez votre connexion internet."
      : "La vérification a échoué.");
  }
  for (const ligne of texte.split(/\r?\n/)) {
    const i = ligne.indexOf(":");
    if (i < 0) continue;
    if (ligne.slice(0, i).trim().toUpperCase() === suffixe) return parseInt(ligne.slice(i + 1).trim() || "0", 10) || 0;
  }
  return 0;
}

/* ---------- normalisations ---------- */
export function normaliserSite(site) {
  site = (site || "").trim();
  if (!site) return "";
  if (!site.includes("://")) site = "https://" + site;
  const message = "Adresse du site invalide (exemple : https://exemple.com).";
  if (site.length > 2048 || /\s/.test(site)) throw new ValueError(message);
  let u;
  try { u = new URL(site); } catch { throw new ValueError(message); }
  if (!["http:", "https:"].includes(u.protocol) || !u.hostname) throw new ValueError(message);
  return site;
}
const normaliser2fa = (v) => ((v || "").trim() ? totp.normaliser(v) : "");

function reponse(f) {
  return async function (...args) {
    try {
      return { ok: true, data: await f.apply(this, args) };
    } catch (e) {
      if (e instanceof CoffreVerrouille) return { ok: false, erreur: e.message, verrouille: true };
      if (e instanceof CoffreError || e instanceof FuiteErreur || e instanceof ValueError) return { ok: false, erreur: e.message };
      return { ok: false, erreur: "Erreur inattendue." };
    }
  };
}

const attendre = (ms) => new Promise((r) => setTimeout(r, ms));
const datePropre = () => new Date().toISOString().slice(0, 10);

/* ---------- plateforme : navigateur par défaut (remplaçable, ex. Android) ---------- */
export const plateformeNavigateur = {
  /** Propose un fichier texte au téléchargement. */
  async enregistrerFichier(nom, texte, mime = "application/octet-stream") {
    const url = URL.createObjectURL(new Blob([texte], { type: mime }));
    const a = document.createElement("a");
    a.href = url; a.download = nom; a.rel = "noopener";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    return nom;
  },
  /** Ouvre le sélecteur de fichiers. Retourne { nom, octets } ou null si annulé. */
  choisirFichier(accept = "") {
    return new Promise((resolve) => {
      const input = document.createElement("input");
      input.type = "file"; if (accept) input.accept = accept;
      input.style.display = "none";
      let fini = false;
      const fin = (v) => { if (!fini) { fini = true; input.remove(); resolve(v); } };
      input.addEventListener("change", async () => {
        const f = input.files && input.files[0];
        if (!f) return fin(null);
        if (f.size > 20 * 1024 * 1024) return fin({ nom: f.name, octets: new Uint8Array(0), trop_gros: true });
        fin({ nom: f.name, octets: new Uint8Array(await f.arrayBuffer()) });
      });
      input.addEventListener("cancel", () => fin(null));
      document.body.appendChild(input);
      input.click();
    });
  },
  ouvrirUrl(url) { window.open(url, "_blank", "noopener,noreferrer"); },
};

/* ---------- l'API ---------- */
export function creerApi({ stockage = new Stockage(), plateforme = plateformeNavigateur, reglages = globalThis.localStorage,
                           delai = DELAI_VERROUILLAGE, appelFetch = globalThis.fetch } = {}) {
  let coffre = null, echecs = 0;

  const ouvert = () => {
    if (!coffre || coffre.estVerrouille) throw new CoffreVerrouille("Le coffre est verrouillé.");
    return coffre;
  };
  const prendreCle = () => { const c = coffre.cleRecuperation; coffre.cleRecuperation = null; return c; };
  const ralentir = async () => { if (echecs >= 3) await attendre(Math.min(echecs - 2, 10) * 1000); };
  const confirmer = async (mdp) => {
    await ralentir();
    try { (await Coffre.ouvrir(stockage, mdp, delai)).verrouiller(); }
    catch (e) { if (e instanceof MotDePasseIncorrect) echecs++; throw e; }
    echecs = 0;
  };
  const lireTheme = () => { try { const t = reglages.getItem("kofre.theme"); return THEMES.includes(t) ? t : "sombre"; } catch { return "sombre"; } };

  const api = {
    etat: reponse(async () => ({ existe: stockage.existe(), verrouille: !coffre || coffre.estVerrouille, theme: lireTheme() })),

    definir_theme: reponse(async (theme) => {
      if (!THEMES.includes(theme)) throw new ValueError("Thème inconnu.");
      try { reglages.setItem("kofre.theme", theme); } catch { /* stockage indisponible : le thème ne sera pas retenu */ }
      return theme;
    }),

    creer: reponse(async (mdp) => { coffre = await Coffre.creer(stockage, mdp, delai); return prendreCle(); }),

    deverrouiller: reponse(async (mdp) => {
      await ralentir();
      try { coffre = await Coffre.ouvrir(stockage, mdp, delai); }
      catch (e) { if (e instanceof MotDePasseIncorrect) echecs++; throw e; }
      echecs = 0;
      return prendreCle(); // toujours null : les anciens coffres (v1) s'ouvrent d'abord sur PC
    }),

    recuperer: reponse(async (cle, nouveau) => {
      await ralentir();
      try { coffre = await Coffre.recuperer(stockage, cle, nouveau, delai); }
      catch (e) { if (e instanceof CleRecuperationIncorrecte) echecs++; throw e; }
      echecs = 0;
      return prendreCle();
    }),

    nouvelle_cle: reponse(async (mdp) => { await confirmer(mdp); return ouvert().regenererCleRecuperation(); }),
    changer_mdp_maitre: reponse(async (actuel, nouveau) => { await confirmer(actuel); await ouvert().changerMotDePasseMaitre(nouveau); return true; }),
    verrouiller: reponse(async () => { if (coffre) coffre.verrouiller(); return true; }),

    lister: reponse(async () => {
      const c = ouvert();
      const entrees = c.lister().map((e) => c.obtenir(e.id));
      const rapport = analyser(entrees);
      const liste = entrees.map((e) => {
        let ident = e.identifiant;
        if (e.categorie === "Banque" && [...ident].length > 4) ident = "•••• " + [...ident].slice(-4).join("");
        return { id: e.id, nom: e.nom, identifiant: ident, categorie: e.categorie, modifie: e.modifie, favori: e.favori };
      });
      liste.sort((a, b) => (a.nom.toLowerCase() < b.nom.toLowerCase() ? -1 : a.nom.toLowerCase() > b.nom.toLowerCase() ? 1 : 0));
      return { entrees: liste, rapport };
    }),

    obtenir: reponse(async (id) => { const e = ouvert().obtenir(id); e.force = force(e.mot_de_passe); return e; }),

    ajouter: reponse(async (nom, identifiant, mdp, categorie = "Autre", notes = "", site = "", favori = false, cle2fa = "") => {
      nom = (nom || "").trim();
      if (!nom || !mdp) throw new CoffreError("Le nom et le mot de passe sont obligatoires.");
      return ouvert().ajouter(nom, identifiant || "", mdp, categorie || "Autre", notes || "",
        normaliserSite(site), !!favori, normaliser2fa(cle2fa));
    }),

    modifier: reponse(async (id, nom, identifiant, mdp, categorie, notes, site = "", favori = false, cle2fa = "") => {
      nom = (nom || "").trim();
      if (!nom || !mdp) throw new CoffreError("Le nom et le mot de passe sont obligatoires.");
      await ouvert().modifier(id, { nom, identifiant: identifiant || "", mot_de_passe: mdp, categorie: categorie || "Autre",
        notes: notes || "", site: normaliserSite(site), favori: !!favori, totp: normaliser2fa(cle2fa) });
      return true;
    }),

    supprimer: reponse(async (id) => { await ouvert().supprimer(id); return true; }),

    generer: reponse(async (longueur = 18, maj = true, chi = true, sym = true) => genererMotDePasse(Number(longueur), !!maj, !!chi, !!sym)),
    generer_maitre: reponse(async () => genererMotDePasseMaitre()),
    evaluer: reponse(async (mdp) => force(mdp)),
    tester_fuite_mdp: reponse(async (mdp) => motDePasseCompromis(mdp, appelFetch)),

    comptes_meme_mdp: reponse(async (mdp, exclureId = "") => {
      const c = ouvert();
      const noms = [];
      for (const e of c.lister()) {
        if (e.id === exclureId) continue;
        const d = c.obtenir(e.id);
        if (d.mot_de_passe === mdp) noms.push(d.nom);
      }
      return noms.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
    }),

    emails: reponse(async () => {
      const c = ouvert();
      const s = new Set();
      for (const e of c.lister()) { const i = c.obtenir(e.id).identifiant; if (i.includes("@")) s.add(i); }
      return [...s].sort();
    }),

    ouvrir_hibp: reponse(async () => { plateforme.ouvrirUrl("https://haveibeenpwned.com/"); return true; }),

    basculer_favori: reponse(async (id) => {
      const c = ouvert();
      const nouveau = !c.obtenir(id).favori;
      await c.modifier(id, { favori: nouveau });
      return nouveau;
    }),

    ouvrir_site: reponse(async (id) => {
      const site = normaliserSite(ouvert().obtenir(id).site); // http(s) uniquement
      if (!site) throw new CoffreError("Aucun site enregistré pour ce compte.");
      plateforme.ouvrirUrl(site);
      return site;
    }),

    code_2fa: reponse(async (id) => {
      const cle = ouvert().obtenir(id, false).totp; // un code affiché ne prolonge pas la session
      if (!cle) throw new CoffreError("Aucune clé 2FA enregistrée pour ce compte.");
      return totp.code(cle);
    }),

    /* ----- corbeille ----- */
    corbeille: reponse(async () => ouvert().listerCorbeille()),
    restaurer_corbeille: reponse(async (id) => { await ouvert().restaurerEntree(id); return true; }),
    supprimer_definitif: reponse(async (id) => { await ouvert().supprimerDefinitivement(id); return true; }),
    vider_corbeille: reponse(async () => ouvert().viderCorbeille()),

    /* ----- import CSV ----- */
    importer_csv: reponse(async () => {
      const c = ouvert();
      const f = await plateforme.choisirFichier(".csv,text/csv,text/plain");
      if (!f) return null;
      if (f.trop_gros) throw new ValueError("Fichier trop volumineux pour un import de mots de passe.");
      const { entrees, ignorees } = lireCsv(f.octets);
      const existants = new Set(c.lister().map((e) => { const d = c.obtenir(e.id); return JSON.stringify([d.nom.toLowerCase(), d.identifiant, d.mot_de_passe]); }));
      const aAjouter = []; let doublons = 0, sitesInvalides = 0, totpInvalides = 0;
      for (const e of entrees) {
        const k = JSON.stringify([e.nom.toLowerCase(), e.identifiant, e.mot_de_passe]);
        if (existants.has(k)) { doublons++; continue; }
        existants.add(k);
        try { e.site = normaliserSite(e.site); } catch { e.site = ""; sitesInvalides++; }
        try { e.totp = normaliser2fa(e.totp); } catch { e.totp = ""; totpInvalides++; }
        aAjouter.push(e);
      }
      const n = await c.ajouterPlusieurs(aAjouter);
      return { importes: n, ignores: ignorees, doublons, sites_invalides: sitesInvalides, totp_invalides: totpInvalides,
        fichier: f.nom, peut_supprimer: false }; // un navigateur ne peut pas supprimer le fichier choisi
    }),
    supprimer_fichier_import: reponse(async () => { throw new CoffreError("Supprimez le fichier CSV vous-même depuis vos fichiers."); }),

    /* ----- fiche de secours (mot de passe maître généré) ----- */
    enregistrer_fiche: reponse(async (mdp) => {
      if (typeof mdp !== "string" || !mdp || mdp.length > 500) throw new ValueError("Aucun mot de passe à enregistrer.");
      const contenu =
        "KOFRE - FICHE DE SECOURS\r\nCréée le " + new Date().toLocaleDateString("fr-FR") + "\r\n\r\n" +
        "Mot de passe maître : " + mdp + "\r\n\r\n" +
        "ATTENTION : ce fichier donne accès à votre coffre à toute personne qui le lit.\r\n" +
        "- Copiez-le sur une clé USB ou imprimez-le, puis supprimez-le de cet appareil.\r\n" +
        "- Ne l'envoyez jamais par WhatsApp, e-mail ou cloud.\r\n" +
        "- Il ne remplace pas la clé de récupération : conservez-la aussi.\r\n";
      return plateforme.enregistrerFichier("KOFRE-fiche-de-secours.txt", contenu, "text/plain");
    }),

    /* ----- sauvegarde et restauration ----- */
    sauvegarder: reponse(async () => {
      const c = ouvert();
      return plateforme.enregistrerFichier("kofre-sauvegarde-" + datePropre() + ".kofre", c.exporterTexte(), "application/octet-stream");
    }),
    restaurer: reponse(async (mdp) => {
      const f = await plateforme.choisirFichier(".kofre,application/octet-stream,text/plain,*/*");
      if (!f) return null;
      if (f.trop_gros) throw new CoffreError("Ce fichier n'est pas une sauvegarde KOFRE valide.");
      let texte;
      try { texte = new TextDecoder("utf-8", { fatal: true }).decode(f.octets); }
      catch { throw new CoffreError("Ce fichier n'est pas une sauvegarde KOFRE valide."); }
      await ralentir();
      let restaure;
      try { restaure = await Coffre.restaurer(texte, mdp, stockage, delai); }
      catch (e) { if (e instanceof MotDePasseIncorrect) echecs++; throw e; }
      echecs = 0;
      if (coffre) coffre.verrouiller();
      coffre = restaure;
      return { cle: prendreCle() };
    }),
  };
  return api;
}
