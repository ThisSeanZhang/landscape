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

const address = env.VITE_PROXY_ADDRESS ?? "localhost";
const port = env.VITE_PROXY_PORT ?? "6443";
const dev_host = env.VITE_DEV_HOST ?? "0.0.0.0";

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
      "landscape-types": path.resolve(__dirname, "../landscape-types/src"),
    },
  },
  server: {
    host: dev_host,
    proxy: {
      "/api": {
        target: `https://${address}:${port}`,
        changeOrigin: true,
        secure: false,
        ws: true,
        configure: (proxy: any, options: any) => {
          // proxy will be an instance of 'http-proxy'
        },
      },
      "/ws": {
        target: `ws://${address}:${port}`,
        changeOrigin: true,
        ws: true,
        rewrite: (path: any) => path.replace(/^\/ws/, ""),
      },
    },
  },
});
