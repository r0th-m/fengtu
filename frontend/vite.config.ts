import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // 绝对基线:SPA 回退在深层路径(/cases/:id)直开/刷新时,
  // 相对基线(./)会让资产 URL 解析成 /cases/assets/... → SPA 回退
  // 返回 text/html → module script 被 MIME 闸拦 → 白屏(8b e2e 实锤)。
  base: "/",
  build: {
    // 产物直落 embed 包内(go:embed 不能引用包外路径);
    // dist 是产物不入库,占位 placeholder.html 除外(见 internal/webui)。
    outDir: "../internal/webui/dist",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8200", changeOrigin: true },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
  },
});
