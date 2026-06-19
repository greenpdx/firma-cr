// SPDX-License-Identifier: GPL-3.0-or-later
// Read-only PDF viewer for the Documento tab: render every page to a canvas in a
// continuous scroll, with zoom and a page indicator. pdf.js's render API draws
// page *content* only — there is no toolbar and no annotation/editor surface, so
// there are simply no edit tools to expose (unlike the native webview viewer).

import * as pdfjs from "pdfjs-dist";
import workerUrl from "pdfjs-dist/build/pdf.worker.mjs?url";

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

type RenderTaskLike = { promise: Promise<unknown>; cancel: () => void };

export interface PdfViewer {
  destroy(): void;
}

const MIN_SCALE = 0.25;
const MAX_SCALE = 5;
const GAP = 12; // px between pages (keep in sync with .pdfv-pages gap)

/// Render `bytes` (a PDF) into `host`, replacing its contents. Returns a handle
/// whose `destroy()` cancels in-flight renders and frees the document.
export async function renderPdf(host: HTMLElement, bytes: ArrayBuffer): Promise<PdfViewer> {
  host.innerHTML = "";
  const root = document.createElement("div");
  root.className = "pdfv";
  root.innerHTML =
    `<div class="pdfv-bar">` +
    `<button class="small" data-z="out" title="Alejar">−</button>` +
    `<span class="pdfv-zoom">100%</span>` +
    `<button class="small" data-z="in" title="Acercar">+</button>` +
    `<button class="small" data-z="fit" title="Ajustar al ancho">Ajustar</button>` +
    `<span class="pdfv-spacer"></span>` +
    `<span class="pdfv-page">–</span>` +
    `</div>` +
    `<div class="pdfv-pages"></div>`;
  host.appendChild(root);

  const bar = root.querySelector<HTMLDivElement>(".pdfv-bar")!;
  const pagesEl = root.querySelector<HTMLDivElement>(".pdfv-pages")!;
  const zoomLabel = root.querySelector<HTMLSpanElement>(".pdfv-zoom")!;
  const pageLabel = root.querySelector<HTMLSpanElement>(".pdfv-page")!;

  const doc = await pdfjs.getDocument({ data: new Uint8Array(bytes) }).promise;
  const numPages = doc.numPages;
  const baseWidth = (await doc.getPage(1)).getViewport({ scale: 1 }).width;

  let scale = 1;
  let gen = 0;
  let tasks: RenderTaskLike[] = [];
  let destroyed = false;

  const cancelTasks = () => { for (const t of tasks) { try { t.cancel(); } catch { /* ignore */ } } tasks = []; };
  const fitScale = () => {
    const avail = pagesEl.clientWidth - 2 * GAP;
    return avail > 0 ? Math.max(MIN_SCALE, avail / baseWidth) : 1;
  };

  async function renderAll(): Promise<void> {
    const myGen = ++gen;
    cancelTasks();
    pagesEl.innerHTML = "";
    zoomLabel.textContent = `${Math.round(scale * 100)}%`;
    const dpr = window.devicePixelRatio || 1;
    for (let i = 1; i <= numPages; i++) {
      if (destroyed || myGen !== gen) return;
      const page = await doc.getPage(i);
      if (destroyed || myGen !== gen) return;
      const viewport = page.getViewport({ scale });
      const canvas = document.createElement("canvas");
      canvas.className = "pdfv-canvas";
      canvas.dataset.page = String(i);
      canvas.width = Math.ceil(viewport.width * dpr);
      canvas.height = Math.ceil(viewport.height * dpr);
      canvas.style.width = `${Math.floor(viewport.width)}px`;
      canvas.style.height = `${Math.floor(viewport.height)}px`;
      pagesEl.appendChild(canvas);
      const ctx = canvas.getContext("2d")!;
      const task = page.render({
        canvasContext: ctx,
        viewport,
        transform: dpr !== 1 ? [dpr, 0, 0, dpr, 0, 0] : undefined,
      }) as unknown as RenderTaskLike;
      tasks.push(task);
      try { await task.promise; } catch { /* cancelled on zoom/destroy */ }
    }
  }

  const setScale = (s: number) => { scale = Math.min(MAX_SCALE, Math.max(MIN_SCALE, s)); void renderAll(); };

  bar.addEventListener("click", (e) => {
    const b = (e.target as HTMLElement).closest<HTMLElement>("[data-z]");
    if (!b) return;
    if (b.dataset.z === "in") setScale(scale * 1.25);
    else if (b.dataset.z === "out") setScale(scale * 0.8);
    else if (b.dataset.z === "fit") setScale(fitScale());
  });

  // Update the page indicator from the page nearest the viewport's middle.
  const onScroll = () => {
    const mid = pagesEl.scrollTop + pagesEl.clientHeight / 2;
    let acc = GAP;
    let cur = 1;
    for (const c of pagesEl.querySelectorAll<HTMLCanvasElement>("canvas")) {
      acc += c.offsetHeight + GAP;
      cur = Number(c.dataset.page);
      if (mid <= acc) break;
    }
    pageLabel.textContent = `${cur} / ${numPages}`;
  };
  pagesEl.addEventListener("scroll", onScroll, { passive: true });

  scale = fitScale();
  await renderAll();
  pageLabel.textContent = `1 / ${numPages}`;

  return {
    destroy() {
      destroyed = true;
      cancelTasks();
      pagesEl.removeEventListener("scroll", onScroll);
      try { void doc.destroy(); } catch { /* ignore */ }
      host.innerHTML = "";
    },
  };
}
