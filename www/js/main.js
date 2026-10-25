/* KOFRE web / Android - démarrage : branche l'API sur la page puis prévient l'interface. */
import { creerApi } from "./api-web.js";
import { estNatif, plateformeNative } from "./native.js";

const natif = estNatif();
window.pywebview = { api: creerApi(natif ? { plateforme: plateformeNative } : {}) };
try { if (navigator.storage && navigator.storage.persist) navigator.storage.persist(); } catch { /* facultatif */ }
if (!natif && "serviceWorker" in navigator) navigator.serviceWorker.register("./sw.js").catch(() => {});
window.dispatchEvent(new Event("pywebviewready"));
