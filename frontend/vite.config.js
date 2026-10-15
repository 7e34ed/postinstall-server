import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  base: "/static/dist/",
  build: {
    manifest: true,
    outDir: resolve(__dirname, "../static/dist"),
    emptyOutDir: true,
    // Vite 8: Rolldown как единый бандлер.
    // Ключ `rollupOptions` продолжает работать (совместимость),
    // но можно использовать `rolldownOptions`.
    rolldownOptions: {
      input: resolve(__dirname, "src/main.js"),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    host: "127.0.0.1",
    cors: true,
  },
});