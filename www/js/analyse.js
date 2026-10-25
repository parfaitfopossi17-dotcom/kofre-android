/* KOFRE web - robustesse des mots de passe (100 % local). Même calcul que la version PC. */

const MOTIFS_FAIBLES = ["password", "motdepasse", "azerty", "qwerty", "123456", "000000",
  "111111", "abcdef", "admin", "letmein", "gabon", "libreville"];

export function force(mdp) {
  if (!mdp) return { score: 0, niveau: "Vide", conseils: ["Le mot de passe est vide."] };
  const car = [...mdp];
  const minuscules = car.some((c) => c !== c.toUpperCase());
  const majuscules = car.some((c) => c !== c.toLowerCase());
  const chiffres = car.some((c) => /\p{Nd}/u.test(c));
  const autres = car.some((c) => !/[\p{L}\p{N}]/u.test(c));
  let alphabet = 26 * minuscules + 26 * majuscules + 10 * chiffres + 32 * autres;
  alphabet = Math.max(alphabet, 10);
  let entropie = car.length * Math.log2(alphabet);

  const conseils = [];
  const bas = mdp.toLowerCase();
  if (MOTIFS_FAIBLES.some((m) => bas.includes(m))) {
    entropie *= 0.3;
    conseils.push("Contient un motif très courant (ex. 123456, azerty, password).");
  }
  if (new Set(car).size <= car.length / 2) {
    entropie *= 0.7;
    conseils.push("Trop de caractères répétés.");
  }
  if (car.length < 12) conseils.push("Trop court : visez au moins 12 caractères.");
  if (!majuscules) conseils.push("Ajoutez des majuscules.");
  if (!chiffres) conseils.push("Ajoutez des chiffres.");
  if (!autres) conseils.push("Ajoutez des symboles (!@#$...).");

  const score = Math.max(0, Math.min(100, Math.round(entropie / 90 * 100)));
  const niveau = score < 25 ? "Très faible" : score < 45 ? "Faible" : score < 65 ? "Moyen" : score < 82 ? "Fort" : "Très fort";
  return { score, niveau, conseils };
}

export function analyser(entrees) {
  if (!entrees.length) return { total: 0, score: 0, niveau: "Vide", faibles: [], reutilises: [], groupes: [] };
  const scores = [], faibles = [], parMdp = new Map();
  for (const e of entrees) {
    const f = force(e.mot_de_passe);
    scores.push(f.score);
    if (f.niveau === "Très faible" || f.niveau === "Faible") faibles.push(e.id);
    if (!parMdp.has(e.mot_de_passe)) parMdp.set(e.mot_de_passe, []);
    parMdp.get(e.mot_de_passe).push(e.id);
  }
  const groupes = [...parMdp.values()].filter((ids) => ids.length > 1);
  const reutilises = groupes.flat();
  const moyenne = scores.reduce((a, b) => a + b, 0) / scores.length;
  const score = Math.round(moyenne * (1 - 0.5 * (reutilises.length / entrees.length)));
  const niveau = score < 45 ? "Faible" : score < 65 ? "Moyen" : "Bon";
  return { total: entrees.length, score, niveau, faibles, reutilises, groupes };
}
