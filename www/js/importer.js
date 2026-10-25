/* KOFRE web - import CSV (Chrome, Edge, Firefox, Bitwarden, KeePass, 1Password…). Lecture 100 % locale. */
import { ValueError } from "./totp.js";

export const TAILLE_MAX = 10 * 1024 * 1024;
export const LIGNES_MAX = 5000;
const CATEGORIES = ["Email", "Banque", "Réseaux sociaux", "École", "Autre"];
const ALIAS = {
  nom: ["name", "title", "titre", "nom", "account", "accountname", "entry", "entrytitle"],
  identifiant: ["username", "loginusername", "loginname", "user", "login", "email", "identifiant", "utilisateur", "useremail", "loginemail"],
  mot_de_passe: ["password", "loginpassword", "motdepasse", "mdp", "pass", "passwd"],
  site: ["url", "loginuri", "website", "weburl", "site", "siteweb", "uri", "address", "adresse"],
  notes: ["note", "notes", "comment", "comments", "commentaire", "commentaires", "extra"],
  totp: ["totp", "logintotp", "otpauth", "otp", "otpurl", "onetimepassword"],
  categorie: ["folder", "grouping", "group", "category", "categorie", "dossier"],
  favori: ["favorite", "favori", "favoris"],
  type: ["type"],
};
const cle = (t) => (t || "").toLowerCase().replace(/[^a-z0-9]/g, "");

function decoder(octets) {
  for (const enc of ["utf-8", "windows-1252"]) {
    try { return new TextDecoder(enc, { fatal: true }).decode(octets).replace(/^\uFEFF/, ""); } catch { /* suivant */ }
  }
  throw new ValueError("Fichier illisible : ce n'est pas un fichier CSV.");
}

function analyserCsv(texte) {
  const premiere = texte.split(/\r\n|\r|\n/, 1)[0] || "";
  const comptes = [",", ";", "\t"].map((d) => premiere.split(d).length - 1);
  const delim = [",", ";", "\t"][comptes.indexOf(Math.max(...comptes))];
  const lignes = []; let ligne = [], champ = "", guillemets = false;
  for (let i = 0; i < texte.length; i++) {
    const c = texte[i];
    if (guillemets) {
      if (c === '"') { if (texte[i + 1] === '"') { champ += '"'; i++; } else guillemets = false; }
      else champ += c;
    } else if (c === '"') guillemets = true;
    else if (c === delim) { ligne.push(champ); champ = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && texte[i + 1] === "\n") i++;
      ligne.push(champ); champ = ""; lignes.push(ligne); ligne = [];
      if (lignes.length > LIGNES_MAX + 2) break;
    } else champ += c;
  }
  if (champ !== "" || ligne.length) { ligne.push(champ); lignes.push(ligne); }
  return lignes;
}

function nomDepuisSite(site) {
  try {
    const h = new URL(site.includes("://") ? site : "https://" + site).hostname;
    return h.startsWith("www.") ? h.slice(4) : h;
  } catch { return ""; }
}

/** octets : Uint8Array du fichier. Retourne { entrees, ignorees } ou lève ValueError. */
export function lireCsv(octets) {
  if (octets.length > TAILLE_MAX) throw new ValueError("Fichier trop volumineux pour un import de mots de passe.");
  const texte = decoder(octets);
  if (texte.includes("\u0000")) throw new ValueError("Fichier illisible : ce n'est pas un fichier CSV.");
  const lignes = analyserCsv(texte);
  if (lignes.length < 2) throw new ValueError("Le fichier ne contient aucun compte.");
  if (lignes.length - 1 > LIGNES_MAX) throw new ValueError(`Trop de lignes (maximum ${LIGNES_MAX}).`);
  const colonnes = {};
  lignes[0].forEach((titre, i) => {
    const k = cle(titre);
    for (const [champ, noms] of Object.entries(ALIAS)) if (noms.includes(k) && !(champ in colonnes)) colonnes[champ] = i;
  });
  if (!("mot_de_passe" in colonnes)) throw new ValueError("Colonnes non reconnues : il faut au moins une colonne « password » ou « mot de passe ».");
  const val = (l, c) => (c in colonnes && colonnes[c] < l.length ? l[colonnes[c]].trim() : "");
  const entrees = []; let ignorees = 0;
  for (const l of lignes.slice(1)) {
    if (!l.some((c) => c.trim())) continue;
    const mdp = colonnes.mot_de_passe < l.length ? l[colonnes.mot_de_passe] : "";
    const genre = val(l, "type").toLowerCase();
    if (!mdp.trim() || (genre && genre !== "login")) { ignorees++; continue; }
    const site = val(l, "site"), ident = val(l, "identifiant");
    const nom = val(l, "nom") || nomDepuisSite(site) || ident || "Sans nom";
    const c = val(l, "categorie").toLowerCase();
    entrees.push({
      nom: nom.slice(0, 200), identifiant: ident.slice(0, 300), mot_de_passe: mdp.slice(0, 1000),
      site: site.slice(0, 2048), notes: val(l, "notes").slice(0, 10000), totp: val(l, "totp").slice(0, 2048),
      categorie: CATEGORIES.find((x) => x.toLowerCase() === c) || "Autre",
      favori: ["1", "true", "yes", "oui", "x"].includes(val(l, "favori").toLowerCase()),
    });
  }
  return { entrees, ignorees };
}
