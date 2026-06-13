import { invoke } from "@tauri-apps/api/core";
import { open as tauriOpen } from "@tauri-apps/plugin-dialog";
import { placeSignature, type Placement } from "./place";

// Tauri desktop shell vs. plain web app. In the browser, card ops go to the
// local /dyn agent (SCManager-style HTTP backend) and files use upload/download.
const IS_TAURI = "__TAURI_INTERNALS__" in window;
// /dyn agent base. In Tauri the page talks to the embedded agent directly at
// 127.0.0.1:41231. In a plain browser we use a *relative* base ("") so requests
// go same-origin and Vite's dev proxy forwards /dyn to the agent — that way
// remote debugging needs only the one dev port forwarded (no CORS, no second
// port). Override either case with VITE_DYN (e.g. http://127.0.0.1:51231).
const DYN = (import.meta as any).env?.VITE_DYN ?? (IS_TAURI ? "http://127.0.0.1:41231" : "");

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
};
const esc = (s: string) =>
  s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));

// Logger — prints to the browser devtools console.
function log(...a: any[]): void {
  console.log("[firma-cr]", ...a);
}
// Log every button click (one delegated listener catches them all).
document.addEventListener("click", (e) => {
  const b = (e.target as HTMLElement)?.closest?.("button");
  if (b) log("click:", b.id || b.textContent?.trim() || "(button)");
});
// Surface any silent failure (a throw in a handler, a rejected promise).
window.addEventListener("error", (e) => log("‼ error:", e.message, e.filename ? `(${e.filename}:${e.lineno})` : ""));
window.addEventListener("unhandledrejection", (e) => log("‼ promesa rechazada:", String((e as PromiseRejectionEvent).reason)));
log("Firma CR GUI", IS_TAURI ? "(Tauri)" : "(web)", "· /dyn =", DYN, "· build", new Date().toLocaleTimeString());

// ---- /dyn helpers --------------------------------------------------------
// fetch with a timeout so a wedged/slow agent surfaces as an error instead of
// hanging the UI forever (card ops can be slow, hence the generous default).
async function fetchT(url: string, opts: RequestInit = {}, ms = 90_000): Promise<Response> {
  const tag = url.replace(DYN, "");
  log(`→ ${opts.method || "GET"} ${tag}`);
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, { ...opts, signal: ctl.signal });
    log(`← ${r.status} ${tag}`);
    return r;
  } catch (e) {
    log(`✗ ${tag}: ${(e as any)?.name === "AbortError" ? "timeout" : e}`);
    if ((e as any)?.name === "AbortError") throw new Error(`tiempo de espera agotado (${ms / 1000}s) — ¿el agente /dyn está respondiendo?`);
    throw e;
  } finally {
    clearTimeout(t);
  }
}
async function dynGet(path: string): Promise<any> {
  const r = await fetchT(`${DYN}${path}`);
  if (!r.ok) throw new Error(`${path.split("?")[0]}: ${r.status} ${(await r.text()) || ""}`.trim());
  return r.json();
}
async function dynInfo(): Promise<string> {
  const j = await dynGet(`/dyn/get_token_info`);
  return j && j.info ? j.info : JSON.stringify(j);
}
function b64(bytes: Uint8Array): string {
  let s = "";
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s);
}
function pemToDer(pem: string): ArrayBuffer {
  const bin = atob(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
/// RSA-OAEP(SHA-256) the PIN with the env public key (matches the agent's decrypt).
async function encryptPin(pubPem: string, pin: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "spki", pemToDer(pubPem), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"],
  );
  const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, new TextEncoder().encode(pin));
  return b64(new Uint8Array(ct));
}
function browserDownload(name: string, blob: Blob): void {
  // Force a Save, not a Firefox preview: octet-stream blob + download attr +
  // advisory type, anchor kept in the DOM, URL alive long enough for the save.
  const url = URL.createObjectURL(new Blob([blob], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name || "documento.pdf";
  a.type = "application/octet-stream";
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  log("descargar:", a.download);
  setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 10_000);
}
/// Full /dyn cryptoshell PDF sign. Returns the signed PDF.
// Signature placement model:
//  - each queued doc carries its OWN placement (QItem.placement);
//  - a new doc inherits `lastPlacement` (the "previous" layout) as its default;
//  - `templates` are named layouts you can save and re-apply.
// All persisted in localStorage.
const PLACE_KEY = "firma-cr.placement";
function loadJSON<T>(key: string): T | null {
  try { const r = localStorage.getItem(key); return r ? (JSON.parse(r) as T) : null; } catch { return null; }
}
let lastPlacement: Placement | null = loadJSON<Placement>(PLACE_KEY);
function setLastPlacement(p: Placement | null): void {
  lastPlacement = p;
  try { if (p) localStorage.setItem(PLACE_KEY, JSON.stringify(p)); } catch { /* ignore */ }
}

async function dynSign(file: File, pin: string, pl: Placement | null): Promise<{ name: string; blob: Blob; signer: string }> {
  log("sign ▶", file.name, `(${file.size} B)`, pl ? "· con ubicación" : "");
  const env = await dynGet(`/dyn/create_env`);
  const id = env.envId;
  log("  create_env →", id);
  await dynGet(`/dyn/connect?env=${id}`);
  log("  connect ok");
  const e = encodeURIComponent(await encryptPin(env.pubKeyPem, pin));
  log("  pin encrypted (RSA-OAEP), login…");
  const login = await dynGet(`/dyn/login?env=${id}&token=0&pin=0&e=${e}`);
  log("  login →", login.success ? "ok" : `FAIL${login.triesLeft != null ? ` (${login.triesLeft} left)` : ""}`);
  if (!login.success) {
    throw new Error("PIN incorrecto o la tarjeta no pudo autenticar" + (login.triesLeft != null ? ` (intentos: ${login.triesLeft})` : ""));
  }
  const certs = await dynGet(`/dyn/get_certstore_certificates?env=${id}`);
  log("  certs →", certs.length, "handle", certs[0]?.handle);
  if (!Array.isArray(certs) || certs.length === 0) throw new Error("la tarjeta no expone un certificado de firma");
  const handle = certs[0].handle;
  const signer = certs[0].subjectDN || certs[0].subject || "";
  const name = file.name.toLowerCase().endsWith(".pdf") ? file.name : file.name + ".pdf";
  const up = await fetchT(`${DYN}/dyn/cryptoshell_add_file?env=${id}&name=${encodeURIComponent(name)}`, {
    method: "POST", body: new Uint8Array(await file.arrayBuffer()),
  });
  if (!up.ok) throw new Error(`add_file: ${up.status} ${(await up.text()) || ""}`.trim());
  log("  add_file ok →", name);
  const files = encodeURIComponent(JSON.stringify([name]));
  const vparam = pl
    ? `&vrect=${pl.rect.map((n) => n.toFixed(1)).join(",")}&vfont=${pl.fontSize}&vpage=${pl.page}`
    : "";
  // PAdES-T: pass the configured TSA so the agent embeds a signature timestamp.
  const tsaParam = cfg.tsaEnabled && cfg.tsa.trim()
    ? `&tsa=${encodeURIComponent(cfg.tsa.trim())}`
    : "";
  if (tsaParam) log("  sello de tiempo →", cfg.tsa.trim());
  const built = await dynGet(`/dyn/cryptoshell_build?env=${id}&type=SIGN&sign_cert=${handle}&sign_key=${handle}&files=${files}${vparam}${tsaParam}`);
  const out = (built.files && built.files[0]) || name.replace(/\.pdf$/i, "-firmado.pdf");
  log("  build(SIGN) →", out);
  const dl = await fetchT(`${DYN}/dyn/download?env=${id}&file=${encodeURIComponent(out)}`);
  if (!dl.ok) throw new Error(`download: ${dl.status}`);
  const blob = await dl.blob();
  log("sign ✔", out, `(${blob.size} B)`, "por", signer);
  return { name: out, blob, signer };
}

// ---- tabs ----------------------------------------------------------------
function showTab(name: string): void {
  document.querySelectorAll<HTMLElement>(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll<HTMLElement>(".tabpane").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
}
document.querySelectorAll<HTMLButtonElement>(".tab").forEach((t) =>
  t.addEventListener("click", () => showTab(t.dataset.tab!)));

// ---- config dialog -------------------------------------------------------
type Method = "pkcs11" | "pkcs12";
const CFG_KEY = "firma-cr.config";
let cfg = loadConfig();
function loadConfig(): { method: Method; module: string; p12: string; tsaEnabled: boolean; tsa: string } {
  const defaults = { method: "pkcs11" as Method, module: "", p12: "", tsaEnabled: false, tsa: "" };
  try {
    const raw = localStorage.getItem(CFG_KEY);
    if (raw) return { ...defaults, ...JSON.parse(raw) };
  } catch { /* ignore */ }
  return defaults;
}
const moduleArg = () => (cfg.module.trim() === "" ? null : cfg.module.trim());
const dialog = $<HTMLDialogElement>("config-dialog");
const selectedMethod = () => (document.querySelector('input[name="method"]:checked') as HTMLInputElement).value as Method;
function toggleMethodGroups(): void {
  const m = selectedMethod();
  $("grp-pkcs11").hidden = m !== "pkcs11";
  $("grp-pkcs12").hidden = m !== "pkcs12";
}
$("btn-config").addEventListener("click", () => {
  (document.querySelector(`input[name="method"][value="${cfg.method}"]`) as HTMLInputElement).checked = true;
  $<HTMLInputElement>("cfg-module").value = cfg.module;
  $<HTMLInputElement>("cfg-p12").value = cfg.p12;
  $<HTMLInputElement>("cfg-tsa-enable").checked = cfg.tsaEnabled;
  $<HTMLInputElement>("cfg-tsa-url").value = cfg.tsa;
  toggleMethodGroups();
  dialog.showModal();
});
document.querySelectorAll('input[name="method"]').forEach((el) => el.addEventListener("change", toggleMethodGroups));
$("cfg-pick-module").addEventListener("click", async () => {
  if (!IS_TAURI) return;
  const sel = await tauriOpen({ multiple: false, filters: [{ name: "PKCS#11 module", extensions: ["so"] }] });
  if (typeof sel === "string") $<HTMLInputElement>("cfg-module").value = sel;
});
$("cfg-pick-p12").addEventListener("click", async () => {
  if (!IS_TAURI) return;
  const sel = await tauriOpen({ multiple: false, filters: [{ name: "PKCS#12", extensions: ["p12", "pfx"] }] });
  if (typeof sel === "string") $<HTMLInputElement>("cfg-p12").value = sel;
});
$("cfg-save").addEventListener("click", () => {
  cfg.method = selectedMethod();
  cfg.module = $<HTMLInputElement>("cfg-module").value;
  cfg.p12 = $<HTMLInputElement>("cfg-p12").value;
  cfg.tsaEnabled = $<HTMLInputElement>("cfg-tsa-enable").checked;
  cfg.tsa = $<HTMLInputElement>("cfg-tsa-url").value.trim();
  localStorage.setItem(CFG_KEY, JSON.stringify(cfg));
  dialog.close();
});
$("cfg-close").addEventListener("click", () => dialog.close());
$("btn-quit").addEventListener("click", () => { if (IS_TAURI) void invoke("quit_app"); else window.close(); });

// ---- Tab 1: Firmar — the sign queue --------------------------------------
type Status = "pending" | "signed" | "error";
interface QItem { file: File; name: string; status: Status; error?: string; placement?: Placement | null; }
let queue: QItem[] = [];
let signedDocs: { name: string; blob: Blob; signer: string }[] = [];

const fileInput = document.createElement("input");
fileInput.type = "file";
fileInput.multiple = true;
fileInput.accept = ".pdf,.txt,.rtf,.odt,.odf,.ods,.odp,application/pdf,text/plain";
// Off-screen (not display:none — some engines won't dispatch .click() to a
// display:none input).
fileInput.style.cssText = "position:fixed;left:-9999px;opacity:0;width:1px;height:1px";
document.body.appendChild(fileInput);
fileInput.addEventListener("change", () => {
  const picked = Array.from(fileInput.files ?? []);
  log(`añadir: ${picked.length} archivo(s) seleccionado(s):`, picked.map((f) => f.name).join(", ") || "(ninguno)");
  // New docs inherit the previous (last-used) layout as their default.
  for (const f of picked) queue.push({ file: f, name: f.name, status: "pending", placement: lastPlacement });
  fileInput.value = "";
  renderQueue();
});
$("btn-add").addEventListener("click", () => {
  log("añadir: abriendo selector de archivos…");
  fileInput.value = "";
  fileInput.click();
});

const PREVIEW = ["Firmado digitalmente por", "(su nombre)", "Fecha: …", "Razon: Firma Digital"];

// Open the placement modal for one doc, pre-positioned at its current layout
// (or the previous default). Stores it per-doc and makes it the new default.
async function placeOnDoc(it: QItem): Promise<Placement | null> {
  log("colocar firma sobre", it.name);
  try {
    const p = await placeSignature(it.file, PREVIEW, it.placement ?? lastPlacement ?? undefined);
    if (p) {
      it.placement = p;
      setLastPlacement(p); // this layout becomes the "previous" default
      log("placement", it.name, JSON.stringify(p));
      renderQueue();
    }
    return p;
  } catch (e) {
    $("result").textContent = "ERROR al previsualizar: " + e;
    console.error("[firma-cr] place ✗", e);
    return null;
  }
}

// "Colocar firma" (header): place once, apply to every pending doc as a template
// and set it as the default for future docs.
$("btn-place").addEventListener("click", async () => {
  const first = queue.find((i) => i.status === "pending" && i.name.toLowerCase().endsWith(".pdf"));
  if (!first) { $("result").textContent = "Añade un PDF primero para colocar la firma."; return; }
  const p = await placeOnDoc(first);
  if (p) {
    queue.filter((i) => i.status === "pending").forEach((i) => (i.placement = p));
    renderQueue();
    $("result").textContent = `Plantilla aplicada a todos los pendientes (pág ${p.page}, ${p.fontSize}pt).`;
  }
});

function badge(it: QItem): string {
  if (it.status === "signed") return '<span class="badge ok">firmado</span>';
  if (it.status === "error") return `<span class="badge err" title="${esc(it.error || "")}">error</span>`;
  return '<span class="badge pending">pendiente</span>';
}
function placeLabel(it: QItem): string {
  const p = it.placement ?? lastPlacement;
  return p ? `📍 pág ${p.page}` : "📍 ubicación";
}

function renderQueue(): void {
  const ul = $("list-tosign");
  ul.innerHTML = "";
  if (!queue.length) { ul.innerHTML = '<li class="empty">Añade documentos (PDF, TXT, RTF, ODF)…</li>'; return; }
  queue.forEach((it, i) => {
    const li = document.createElement("li");
    li.innerHTML = `<span class="name">${esc(it.name)}</span>${badge(it)}`;
    const place = document.createElement("button");
    place.className = "small"; place.textContent = placeLabel(it);
    place.title = "Ubicación de la firma en este documento";
    place.disabled = !it.name.toLowerCase().endsWith(".pdf") || it.status === "signed";
    place.addEventListener("click", () => placeOnDoc(it));
    const rm = document.createElement("button");
    rm.className = "small"; rm.textContent = "✕"; rm.title = "Quitar";
    rm.addEventListener("click", () => { queue.splice(i, 1); renderQueue(); });
    li.append(place, rm);
    ul.appendChild(li);
  });
}
function renderSigned(): void {
  const ul = $("list-signed");
  ul.innerHTML = "";
  if (!signedDocs.length) { ul.innerHTML = '<li class="empty">Los documentos firmados aparecerán aquí.</li>'; return; }
  signedDocs.forEach((d) => {
    const li = document.createElement("li");
    li.innerHTML = `<span class="name">${esc(d.name)}</span>`;
    const view = document.createElement("button");
    view.className = "small"; view.textContent = "Ver";
    view.addEventListener("click", () => openDoc(d.name, d.blob, d.signer));
    const dl = document.createElement("button");
    dl.className = "small"; dl.textContent = "⬇"; dl.title = "Descargar";
    dl.addEventListener("click", () => browserDownload(d.name, d.blob));
    li.append(view, dl);
    ul.appendChild(li);
  });
}
$("btn-clear-signed").addEventListener("click", () => { signedDocs = []; renderSigned(); });

// Sign-all: one PIN prompt, then sign every pending doc.
const pinDialog = $<HTMLDialogElement>("pin-dialog");
const pinInput = $<HTMLInputElement>("pin-input");
$("btn-sign-all").addEventListener("click", () => {
  if (!queue.some((i) => i.status === "pending")) { $("result").textContent = "No hay documentos pendientes."; return; }
  pinInput.value = "";
  pinDialog.showModal();
  pinInput.focus();
});
$("pin-cancel").addEventListener("click", () => { pinInput.value = ""; pinDialog.close(); });
pinInput.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); $("pin-ok").click(); } });
$("pin-ok").addEventListener("click", async () => {
  const pin = pinInput.value;
  if (!pin) { pinInput.focus(); return; }
  pinDialog.close();
  const res = $("result");
  const pending = queue.filter((i) => i.status === "pending");
  let ok = 0;
  log(`firmar todo: ${pending.length} pendiente(s)`);
  for (const it of pending) {
    res.textContent = `firmando ${it.name}…`;
    try {
      if (!it.name.toLowerCase().endsWith(".pdf")) {
        throw new Error("por ahora solo PDF (CAdES para TXT/RTF/ODF: pendiente en el backend)");
      }
      const signed = await dynSign(it.file, pin, it.placement ?? lastPlacement ?? null);
      it.status = "signed";
      signedDocs.unshift(signed);
      ok++;
    } catch (e) {
      it.status = "error";
      it.error = String(e);
      console.error("[firma-cr] sign ✗", it.name, e);
    }
    renderQueue();
    renderSigned();
  }
  log(`firmar todo: ${ok}/${pending.length} ok`);
  pinInput.value = ""; // wipe the PIN
  res.textContent = `Firmados ${ok}/${pending.length}.` + (ok ? ' Ábrelos en «Documento» o descárgalos.' : "");
  if (ok && signedDocs[0]) openDoc(signedDocs[0].name, signedDocs[0].blob, signedDocs[0].signer);
});

// ---- Tab 2: Tarjeta — card manager ---------------------------------------
$("btn-info").addEventListener("click", async () => {
  const detail = $("card-detail");
  const items = $("card-items");
  detail.textContent = "leyendo tarjeta…";
  log("leer tarjeta…");
  try {
    const info = IS_TAURI ? await invoke<string>("card_info", { module: moduleArg(), slot: null }) : await dynInfo();
    log("tarjeta ok");
    detail.textContent = info;
    items.innerHTML = "";
    const li = document.createElement("li");
    li.className = "sel";
    li.textContent = "🪪 Token / Tarjeta";
    li.addEventListener("click", () => {
      items.querySelectorAll("li").forEach((x) => x.classList.remove("sel"));
      li.classList.add("sel");
      detail.textContent = info;
    });
    items.appendChild(li);
  } catch (e) {
    detail.textContent = "ERROR: " + e;
  }
});
document.querySelectorAll<HTMLButtonElement>(".rail-btn").forEach((b) =>
  b.addEventListener("click", () => {
    document.querySelectorAll(".rail-btn").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    $("mgr-list-title").textContent = b.dataset.view === "certs" ? "Certificados" : "Tarjeta";
  }));

// ---- Tab 3: Documento — format-aware viewer ------------------------------
let docUrl: string | null = null;
async function openDoc(name: string, blob: Blob, signer?: string): Promise<void> {
  showTab("documento");
  $("doc-title").textContent = name;
  const dl = $<HTMLButtonElement>("doc-download");
  dl.disabled = false;
  dl.onclick = () => browserDownload(name, blob);
  // Signature status banner (who signed it).
  const sig = $("doc-sig");
  if (signer) {
    const cn = signer.match(/CN=([^,]+)/i)?.[1] || signer;
    sig.innerHTML = `<span class="ok">✔ Firmado</span> por <b>${esc(cn)}</b> · PAdES · SHA-256`;
    sig.hidden = false;
  } else {
    sig.hidden = true;
  }
  const view = $("doc-view");
  if (docUrl) { URL.revokeObjectURL(docUrl); docUrl = null; }
  const ext = (name.toLowerCase().split(".").pop() || "");
  if (ext === "pdf") {
    docUrl = URL.createObjectURL(new Blob([blob], { type: "application/pdf" }));
    view.innerHTML = `<iframe src="${docUrl}#toolbar=1"></iframe>`;
  } else if (ext === "txt") {
    const pre = document.createElement("pre");
    pre.textContent = await blob.text();
    view.innerHTML = "";
    view.appendChild(pre);
  } else {
    view.innerHTML = `<div class="placeholder">Vista previa no disponible para «.${esc(ext)}».<br>Usa «Descargar» para abrirlo en tu aplicación.</div>`;
  }
}

// initial render
renderQueue();
renderSigned();
