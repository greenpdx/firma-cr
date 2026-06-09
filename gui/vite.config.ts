import { defineConfig } from "vite";

// Tauri expects a fixed dev port and ignores Vite's HMR websocket over the
// custom protocol; 1420 is the create-tauri-app default.
export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    // matches tauri.conf.json `frontendDist: "../dist"`
    outDir: "dist",
    target: "es2020",
    sourcemap: true,
  },
});
