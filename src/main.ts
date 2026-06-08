import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
};

type Method = "pkcs11" | "pkcs12";

interface Config {
  method: Method;
  module: string; // PKCS#11 .so path ("" = backend default)
  p12: string;    // PKCS#12 file path
}

// Persisted (non-secret) config. The PIN is NEVER stored and is not held in
// any variable — it is read from the field at sign time and wiped immediately.
const CFG_KEY = "firma-cr.config";
let cfg: Config = loadConfig();

let inputPath: string | null = null;
let outputPath: string | null = null;

function loadConfig(): Config {
  try {
    const raw = localStorage.getItem(CFG_KEY);
    if (raw) return { method: "pkcs11", module: "", p12: "", ...JSON.parse(raw) };
  } catch { /* ignore */ }
  return { method: "pkcs11", module: "", p12: "" };
}

function saveConfig(): void {
  localStorage.setItem(CFG_KEY, JSON.stringify({ method: cfg.method, module: cfg.module, p12: cfg.p12 }));
}

function moduleArg(): string | null {
  return cfg.module.trim() === "" ? null : cfg.module.trim();
}

function refreshSummary(): void {
  $("sum-method").textContent =
    cfg.method === "pkcs11" ? "Smart card (PKCS#11)" : "PKCS#12 file";
  $("sum-source").textContent =
    cfg.method === "pkcs11"
      ? (cfg.module || "(default) /usr/lib/firma-cr/libfirma_cr_pkcs11.so")
      : (cfg.p12 || "(no .p12 selected)");
}

// ---------------------------------------------------------------- config UI
const dialog = $<HTMLDialogElement>("config-dialog");

function syncDialogFromCfg(): void {
  (document.querySelector(`input[name="method"][value="${cfg.method}"]`) as HTMLInputElement).checked = true;
  $<HTMLInputElement>("cfg-module").value = cfg.module;
  $<HTMLInputElement>("cfg-p12").value = cfg.p12;
  toggleMethodGroups();
}

function selectedMethod(): Method {
  return (document.querySelector('input[name="method"]:checked') as HTMLInputElement).value as Method;
}

function toggleMethodGroups(): void {
  const m = selectedMethod();
  $("grp-pkcs11").hidden = m !== "pkcs11";
  $("grp-pkcs12").hidden = m !== "pkcs12";
}

$("btn-config").addEventListener("click", () => {
  syncDialogFromCfg();
  dialog.showModal();
});

// Exit button: quits the whole process (stops the embedded /dyn agent too).
$("btn-quit").addEventListener("click", () => { void invoke("quit_app"); });
document.querySelectorAll('input[name="method"]').forEach((el) =>
  el.addEventListener("change", toggleMethodGroups),
);

$("cfg-pick-module").addEventListener("click", async () => {
  const sel = await open({ multiple: false, filters: [{ name: "PKCS#11 module", extensions: ["so"] }] });
  if (typeof sel === "string") $<HTMLInputElement>("cfg-module").value = sel;
});
$("cfg-pick-p12").addEventListener("click", async () => {
  const sel = await open({ multiple: false, filters: [{ name: "PKCS#12", extensions: ["p12", "pfx"] }] });
  if (typeof sel === "string") $<HTMLInputElement>("cfg-p12").value = sel;
});

$("cfg-save").addEventListener("click", () => {
  cfg.method = selectedMethod();
  cfg.module = $<HTMLInputElement>("cfg-module").value;
  cfg.p12 = $<HTMLInputElement>("cfg-p12").value;
  saveConfig();
  refreshSummary();
  dialog.close();
});
$("cfg-close").addEventListener("click", () => dialog.close());

// ---------------------------------------------------------------- actions
$("btn-info").addEventListener("click", async () => {
  const out = $("info");
  if (cfg.method === "pkcs12") {
    out.textContent = "PKCS#12 mode: card info not applicable (no token).";
    return;
  }
  out.textContent = "reading card…";
  try {
    out.textContent = await invoke<string>("card_info", { module: moduleArg(), slot: null });
  } catch (e) {
    out.textContent = "ERROR: " + e;
  }
});

$("btn-pick-in").addEventListener("click", async () => {
  const sel = await open({ multiple: false, filters: [{ name: "PDF", extensions: ["pdf"] }] });
  if (typeof sel === "string") {
    inputPath = sel;
    $("in-path").textContent = sel;
    if (!outputPath) {
      outputPath = sel.replace(/\.pdf$/i, "") + ".signed.pdf";
      $("out-path").textContent = outputPath;
    }
  }
});

$("btn-pick-out").addEventListener("click", async () => {
  const sel = await save({ defaultPath: outputPath ?? "signed.pdf", filters: [{ name: "PDF", extensions: ["pdf"] }] });
  if (sel) { outputPath = sel; $("out-path").textContent = sel; }
});

// PIN is entered in a popup dialog at sign time (GAUDI-style), never inline.
const pinDialog = $<HTMLDialogElement>("pin-dialog");
const pinInput = $<HTMLInputElement>("pin-input");

$("btn-sign").addEventListener("click", () => {
  const res = $("result");
  if (!inputPath) { res.textContent = "Pick a PDF first."; return; }
  if (!outputPath) { res.textContent = "Pick an output path first."; return; }
  pinInput.value = "";
  pinDialog.showModal();
  pinInput.focus();
});

$("pin-cancel").addEventListener("click", () => {
  pinInput.value = "";
  pinDialog.close();
});

pinInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); $("pin-ok").click(); }
});

$("pin-ok").addEventListener("click", async () => {
  const pin = pinInput.value;
  if (!pin) { pinInput.focus(); return; }
  pinDialog.close();
  const res = $("result");
  res.textContent = "signing…";
  try {
    res.textContent = await invoke<string>("sign_pdf", {
      method: cfg.method,
      module: moduleArg(),
      pkcs12Path: cfg.method === "pkcs12" ? (cfg.p12 || null) : null,
      slot: null,
      inputPath,
      outputPath,
      password: pin,
      reason: $<HTMLInputElement>("reason").value || null,
      location: $<HTMLInputElement>("location").value || null,
    });
  } catch (e) {
    res.textContent = "ERROR: " + e;
  } finally {
    pinInput.value = ""; // wipe the PIN right after use — never retained
  }
});

refreshSummary();
