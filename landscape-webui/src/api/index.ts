import type { AxiosInstance } from "axios";
import router from "@/router";
import i18n from "@/i18n";
import { LANDSCAPE_TOKEN_KEY } from "@/lib/common";

/**
 * Apply common interceptors (auth token, token refresh, error handling)
 * to any axios instance.
 */
export function applyInterceptors(instance: AxiosInstance): AxiosInstance {
  instance.interceptors.request.use(
    (config) => {
      const token = localStorage.getItem(LANDSCAPE_TOKEN_KEY);
      if (token) {
        config.headers["Authorization"] = `Bearer ${token}`;
      }
      return config;
    },
    (error) => {
      return Promise.reject(error);
    },
  );

  instance.interceptors.response.use(
    (response) => {
      const newToken = response.headers["x-refresh-token"];
      if (newToken) {
        localStorage.setItem(LANDSCAPE_TOKEN_KEY, newToken);
      }
      return response.data;
    },
    (error) => {
      if (error.response != undefined && error.response.status != undefined) {
        const code = error.response.status;
        const { error_id, message, args } = error.response.data;
        if (code === 401) {
          localStorage.removeItem(LANDSCAPE_TOKEN_KEY);

          const currentPath = router.currentRoute.value.fullPath;
          router.push({
            path: "/login",
            state: currentPath === "/login" ? {} : { redirect: currentPath },
          });
        }

        const errorKey = error_id ? `errors.${error_id}` : "";
        const displayMsg =
          errorKey && i18n.global.te(errorKey)
            ? (i18n.global.t(errorKey, args || {}) as string)
            : message;

        if (displayMsg && window.$message) {
          window.$message.error(displayMsg);
        }
        return Promise.reject(error.response.data);
      }
      return Promise.reject(error);
    },
  );

  return instance;
}
