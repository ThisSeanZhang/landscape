import type { AxiosInstance } from "axios";
import router from "@/router";
import i18n from "@/i18n";
import { LANDSCAPE_TOKEN_KEY } from "@/lib/common";

function formatApiErrorTemplate(
  template: string,
  args: Record<string, unknown> | undefined,
): string {
  if (!args) return template;
  return template.replace(/\{([^}]+)\}/g, (_m: string, key: string) => {
    const value = args[key];
    return value == null ? `{${key}}` : String(value);
  });
}

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

        const locale =
          typeof i18n.global.locale === "string"
            ? i18n.global.locale
            : i18n.global.locale.value;
        const localeMessages = i18n.global.getLocaleMessage(locale) as Record<
          string,
          unknown
        >;
        const errorsMap = localeMessages.errors as
          Record<string, string> | undefined;
        const flatTemplate =
          error_id && errorsMap ? errorsMap[error_id] : undefined;

        const errorKey = error_id ? `errors.${error_id}` : "";
        const displayMsg = flatTemplate
          ? formatApiErrorTemplate(flatTemplate, args || {})
          : errorKey && i18n.global.te(errorKey)
            ? (i18n.global.t(errorKey, args || {}) as string)
            : message;

        if (displayMsg && window.$message && !error.config?.silent) {
          window.$message.error(displayMsg);
        }
        return Promise.reject(error.response.data);
      }
      return Promise.reject(error);
    },
  );

  return instance;
}
