import { createApp } from "vue";
import { createPinia } from "pinia";
import piniaPluginPersistedstate from "pinia-plugin-persistedstate";
import axios from "axios";
import router from "./router";
import i18n from "./i18n";

import "vfonts/Lato.css";
import "vfonts/FiraCode.css";

import "./style.css";

import App from "./App.vue";
import { useMessage } from "naive-ui";
import { setAxiosInstance } from "landscape-types/mutator";
import { applyInterceptors } from "./api";

declare global {
  interface Window {
    $message: ReturnType<typeof useMessage>;
  }
}

// Initialize orval's axios instance (no baseURL suffix — orval generates full paths)
const orvalAxios = applyInterceptors(axios.create({ timeout: 30000 }));
setAxiosInstance(orvalAxios);

const pinia = createPinia();
pinia.use(piniaPluginPersistedstate);

createApp(App).use(i18n).use(router).use(pinia).mount("#app");
