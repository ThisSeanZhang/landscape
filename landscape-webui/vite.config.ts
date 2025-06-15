import { defineConfig, loadEnv } from "vite";
import vue from "@vitejs/plugin-vue";
import path from "node:path";
import { readFileSync } from "fs";

import basicSsl from "@vitejs/plugin-basic-ssl";
import AutoImport from "unplugin-auto-import/vite";
import Components from "unplugin-vue-components/vite";
import { NaiveUiResolver } from "unplugin-vue-components/resolvers";

const pkg = JSON.parse(readFileSync("./package.json", "utf-8"));

const env = loadEnv("development", "./");

// https://vitejs.dev/config/
export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  plugins: [
    basicSsl(),
    vue(),
    AutoImport({
      imports: [
        "vue",
        {
          "naive-ui": [
            "useDialog",
            "useMessage",
            "useNotification",
            "useLoadingBar",
          ],
        },
      ],
    }),
    Components({
      resolvers: [NaiveUiResolver()],
    }),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      "*": path.resolve(""),
    },
  },
  server: {
    host: "localhost",
    port: 5173,
    proxy: {
      "/api": {
        target: `https://${env.VITE_PROXY_ADDRESS}`,
        changeOrigin: true,
        secure: false,
        configure: (proxy: any, options: any) => {
          // proxy will be an instance of 'http-proxy'
        },
      },
      "/ws": {
        target: `ws://${env.VITE_PROXY_ADDRESS}`,
        changeOrigin: true,
        ws: true,
        rewrite: (path: any) => path.replace(/^\/ws/, ""),
      },
    },
  },
});
