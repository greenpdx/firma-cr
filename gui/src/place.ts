// Interactive signature placement: render a PDF page to a canvas, overlay a
// draggable + resizable box, and return the chosen rectangle in PDF points
// (origin bottom-left) — ready to pass as a VisibleAppearance to the signer.
import * as pdfjs from "pdfjs-dist";
import workerUrl from "pdfjs-dist/build/pdf.worker.mjs?url";

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

export interface Placement {
  page: number;
  /** PDF points, origin bottom-left: [llx, lly, urx, ury]. */
  rect: [number, number, number, number];
  fontSize: number;
}
export interface NamedPlacement extends Placement {
  name: string;
}

// Named layout templates, persisted (shared with the modal's dropdown).
const TPL_KEY = "firma-cr.templates";
export function loadTemplates(): NamedPlacement[] {
  try {
    const r = localStorage.getItem(TPL_KEY);
    return r ? (JSON.parse(r) as NamedPlacement[]) : [];
  } catch {
    return [];
  }
}
function saveTemplates(t: NamedPlacement[]): void {
  try { localStorage.setItem(TPL_KEY, JSON.stringify(t)); } catch { /* ignore */ }
}

const DEFAULTS = { wPt: 300, hPt: 90, fontSize: 8 };

/**
 * Open a modal to place the signature box on `file`'s first page. Resolves to
 * the chosen Placement, or null if cancelled. `preview` lines are shown inside
 * the box as a live preview of the stamp text.
 */
export async function placeSignature(
  file: File,
  preview: string[],
  initial?: Placement,
): Promise<Placement | null> {
  const data = new Uint8Array(await file.arrayBuffer());
  const pdf = await pdfjs.getDocument({ data }).promise;
  const pageNum = 1;
  const page = await pdf.getPage(pageNum);

  // Render the page to a canvas, fitting the whole page within the modal (both
  // width and height) so the box is always visible without scrolling.
  const base = page.getViewport({ scale: 1 });
  const maxW = Math.min(720, window.innerWidth * 0.86);
  const maxH = window.innerHeight * 0.62;
  const scale = Math.min(maxW / base.width, maxH / base.height); // canvas px per PDF point
  const viewport = page.getViewport({ scale });
  const canvas = document.createElement("canvas");
  canvas.width = Math.ceil(viewport.width);
  canvas.height = Math.ceil(viewport.height);
  const ctx = canvas.getContext("2d")!;
  await page.render({ canvasContext: ctx, viewport }).promise;

  return new Promise<Placement | null>((resolve) => {
    // ---- modal scaffold ----
    const back = el("div", "place-backdrop");
    const modal = el("div", "place-modal");
    const head = el("div", "place-head");
    head.innerHTML = `<b>Coloca la firma</b> <span class="hint">arrastra para mover, esquina ◢ para redimensionar</span>`;
    const stage = el("div", "place-stage");
    canvas.className = "place-canvas";
    const boxEl = el("div", "place-box");
    const grip = el("div", "place-grip");
    boxEl.appendChild(grip);
    stage.append(canvas, boxEl);

    // controls — font size + template dropdown + save, all inside the popup
    const ctrls = el("div", "place-ctrls");
    const fontInput = document.createElement("input");
    fontInput.type = "range"; fontInput.min = "6"; fontInput.max = "16"; fontInput.step = "1";
    fontInput.value = String(DEFAULTS.fontSize);
    const fontLbl = el("span", "hint");
    const tplSel = document.createElement("select");
    tplSel.className = "small";
    const tplSave = btn("Guardar plantilla", "small");
    const accept = btn("Firmar aquí", "primary small");
    const cancel = btn("Cancelar", "small");
    const ctrlsLeft = el("div");
    ctrlsLeft.append(label("Tamaño "), fontInput, fontLbl, tplSel, tplSave);
    const ctrlsRight = el("div");
    ctrlsRight.append(cancel, accept);
    ctrls.append(ctrlsLeft, ctrlsRight);

    modal.append(head, stage, ctrls);
    back.appendChild(modal);
    document.body.appendChild(back);

    // ---- box state (CSS px relative to the canvas) ----
    let bw = Math.min(DEFAULTS.wPt * scale, canvas.width - 8);
    let bh = Math.min(DEFAULTS.hPt * scale, canvas.height - 8);
    let bx = Math.max(0, (canvas.width - bw) / 2); // start centred = always visible
    let by = Math.max(0, (canvas.height - bh) / 2);
    let fontSize = DEFAULTS.fontSize;

    const draw = () => {
      boxEl.style.left = `${bx}px`;
      boxEl.style.top = `${by}px`;
      boxEl.style.width = `${bw}px`;
      boxEl.style.height = `${bh}px`;
      boxEl.style.fontSize = `${fontSize * scale}px`;
      fontLbl.textContent = `${fontSize} pt`;
      boxEl.dataset.text = preview.join("\n");
    };
    // Apply a saved placement (PDF points → canvas px, Y-flip) to the box.
    const applyPlacement = (p: Placement) => {
      const [llx, lly, urx, ury] = p.rect;
      bw = (urx - llx) * scale;
      bh = (ury - lly) * scale;
      bx = llx * scale;
      by = (base.height - ury) * scale;
      fontSize = p.fontSize;
      fontInput.value = String(fontSize);
      draw();
    };
    // Current box → Placement (PDF points), from the actual rendered rects.
    const currentPlacement = (): Placement => {
      const cr = canvas.getBoundingClientRect();
      const br = boxEl.getBoundingClientRect();
      const kx = base.width / cr.width, ky = base.height / cr.height;
      const relLeft = br.left - cr.left, relTop = br.top - cr.top;
      return {
        page: pageNum,
        rect: [
          relLeft * kx,
          base.height - (relTop + br.height) * ky,
          (relLeft + br.width) * kx,
          base.height - relTop * ky,
        ],
        fontSize,
      };
    };

    // Template dropdown + save (in the popup).
    let tpls = loadTemplates();
    const refreshTpl = () => {
      tplSel.innerHTML = "";
      const def = document.createElement("option");
      def.value = ""; def.textContent = tpls.length ? "Plantilla…" : "Sin plantillas";
      tplSel.appendChild(def);
      tpls.forEach((t, i) => {
        const o = document.createElement("option");
        o.value = String(i); o.textContent = t.name;
        tplSel.appendChild(o);
      });
    };
    refreshTpl();
    tplSel.addEventListener("change", () => {
      if (tplSel.value === "") return;
      const t = tpls[Number(tplSel.value)];
      if (t) applyPlacement(t);
    });
    tplSave.addEventListener("click", () => {
      const name = prompt("Nombre de la plantilla:", `Plantilla ${tpls.length + 1}`);
      if (!name) return;
      tpls = [...tpls, { ...currentPlacement(), name }];
      saveTemplates(tpls);
      refreshTpl();
    });

    if (initial) applyPlacement(initial); else draw();

    // ---- drag (move) + resize ----
    let mode: "move" | "resize" | null = null;
    let sx = 0, sy = 0, ox = 0, oy = 0, ow = 0, oh = 0;
    const onDown = (e: PointerEvent, m: "move" | "resize") => {
      mode = m; sx = e.clientX; sy = e.clientY; ox = bx; oy = by; ow = bw; oh = bh;
      (e.target as HTMLElement).setPointerCapture(e.pointerId);
      e.preventDefault();
    };
    boxEl.addEventListener("pointerdown", (e) => { if (e.target === grip) return; onDown(e, "move"); });
    grip.addEventListener("pointerdown", (e) => onDown(e, "resize"));
    window.addEventListener("pointermove", (e) => {
      if (!mode) return;
      const dx = e.clientX - sx, dy = e.clientY - sy;
      if (mode === "move") {
        bx = clamp(ox + dx, 0, canvas.width - bw);
        by = clamp(oy + dy, 0, canvas.height - bh);
      } else {
        bw = clamp(ow + dx, 60, canvas.width - bx);
        bh = clamp(oh + dy, 30, canvas.height - by);
      }
      draw();
    });
    window.addEventListener("pointerup", () => { mode = null; });
    fontInput.addEventListener("input", () => { fontSize = Number(fontInput.value); draw(); });

    const close = (result: Placement | null) => { back.remove(); resolve(result); };
    cancel.addEventListener("click", () => close(null));
    back.addEventListener("click", (e) => { if (e.target === back) close(null); });
    accept.addEventListener("click", () => close(currentPlacement()));
  });
}

// ---- tiny DOM helpers ----
function el(tag: string, cls?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  return e;
}
function btn(text: string, cls: string): HTMLButtonElement {
  const b = document.createElement("button");
  b.className = cls; b.textContent = text; b.type = "button";
  return b;
}
function label(text: string): HTMLElement {
  const s = document.createElement("span");
  s.className = "hint"; s.textContent = text;
  return s;
}
function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, v));
}
