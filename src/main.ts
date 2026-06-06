import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
};

let inputPath: string | null = null;
let outputPath: string | null = null;

const moduleArg = (): string | null => {
  const m = $<HTMLInputElement>("module").value.trim();
  return m === "" ? null : m;
};

$("btn-info").addEventListener("click", async () => {
  const out = $("info");
  out.textContent = "reading card…";
  try {
    out.textContent = await invoke<string>("card_info", {
      module: moduleArg(),
      slot: null,
    });
  } catch (e) {
    out.textContent = "ERROR: " + e;
  }
});

$("btn-pick-in").addEventListener("click", async () => {
  const sel = await open({
    multiple: false,
    filters: [{ name: "PDF", extensions: ["pdf"] }],
  });
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
  const sel = await save({
    defaultPath: outputPath ?? "signed.pdf",
    filters: [{ name: "PDF", extensions: ["pdf"] }],
  });
  if (sel) {
    outputPath = sel;
    $("out-path").textContent = sel;
  }
});

$("btn-sign").addEventListener("click", async () => {
  const res = $("result");
  const pin = $<HTMLInputElement>("pin").value;
  if (!inputPath) { res.textContent = "Pick a PDF first."; return; }
  if (!outputPath) { res.textContent = "Pick an output path first."; return; }
  if (!pin) { res.textContent = "Enter the card PIN."; return; }
  res.textContent = "signing… (PIN is checked on-card; this may take a second)";
  try {
    res.textContent = await invoke<string>("sign_pdf", {
      module: moduleArg(),
      slot: null,
      inputPath,
      outputPath,
      pin,
      reason: $<HTMLInputElement>("reason").value || null,
      location: $<HTMLInputElement>("location").value || null,
    });
    $<HTMLInputElement>("pin").value = ""; // don't leave the PIN in the field
  } catch (e) {
    res.textContent = "ERROR: " + e;
  }
});
