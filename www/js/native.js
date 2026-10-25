/* KOFRE Android : enregistrement et ouverture via les fonctions natives du téléphone (Capacitor). */
import { plateformeNavigateur } from "./api-web.js";

export const estNatif = () => !!(window.Capacitor && window.Capacitor.isNativePlatform && window.Capacitor.isNativePlatform());

export const plateformeNative = {
  /** Écrit la sauvegarde dans le cache puis ouvre le partage Android (Fichiers, Drive, WhatsApp, e-mail…). */
  async enregistrerFichier(nom, texte) {
    const { Filesystem, Share } = window.Capacitor.Plugins;
    const r = await Filesystem.writeFile({ path: nom, data: texte, directory: "CACHE", encoding: "utf8" });
    try {
      await Share.share({ title: nom, files: [r.uri], dialogTitle: "Enregistrer la sauvegarde KOFRE" });
    } catch (e) {
      if (/cancel/i.test(String((e && e.message) || e))) return null; // fenêtre de partage fermée
      throw e;
    } finally {
      try { await Filesystem.deleteFile({ path: nom, directory: "CACHE" }); } catch { /* sans importance */ }
    }
    return nom;
  },
  choisirFichier: (accept) => plateformeNavigateur.choisirFichier(accept),
  ouvrirUrl(url) {
    const B = window.Capacitor.Plugins.Browser;
    if (B && B.open) B.open({ url }); else window.open(url, "_blank", "noopener,noreferrer");
  },
};
