import { defineConfig } from "vite";
import { resolve } from "path";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(({ command }) => ({
  base: command === "serve" ? "/" : "/static/",   // ← ключевая строка
  plugins: [tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    host: "127.0.0.1",
    cors: true,
  },
  build: {
    manifest: true,
    outDir: resolve(__dirname, "../static/dist"),
    emptyOutDir: true,
    rolldownOptions: {
      input: resolve(__dirname, "src/main.js"),
    },
  },
}));