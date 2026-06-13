import { defineConfig } from "vite";

// Tauri expects a fixed dev port and ignores Vite's HMR websocket over the
// custom protocol; 1420 is the create-tauri-app default.
// Dev-server proxy for the /dyn agent. A plain browser (e.g. remote debugging
// over a single forwarded port) can then call /dyn *same-origin* and Vite
// forwards it to the local agent — one port, no CORS, no hardcoded :41231 in the
// page. Tauri builds talk to the agent directly and don't use this. Override the
// target with VITE_DYN_TARGET for a test agent (e.g. on :51231).
const DYN_TARGET = process.env.VITE_DYN_TARGET ?? "http://127.0.0.1:41231";

export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    proxy: {
      "/dyn": { target: DYN_TARGET, changeOrigin: true },
    },
  },
  build: {
    // matches tauri.conf.json `frontendDist: "../dist"`
    outDir: "dist",
    target: "es2020",
    sourcemap: true,
  },
});
