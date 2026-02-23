import type { AxiosInstance, AxiosRequestConfig } from "axios";

let _axiosInstance: AxiosInstance;

/**
 * Set the axios instance used by all generated API functions.
 * Must be called before any API call.
 *
 * @example
 * ```ts
 * import axios from "axios";
 * import { setAxiosInstance } from "landscape-types/api/mutator";
 *
 * const instance = axios.create({
 *   baseURL: "https://my-router:8443/api/src",
 * });
 * setAxiosInstance(instance);
 * ```
 */
export function setAxiosInstance(instance: AxiosInstance) {
  _axiosInstance = instance;
}

export const customInstance = <T>(config: AxiosRequestConfig): Promise<T> => {
  if (!_axiosInstance) {
    throw new Error(
      "Axios instance not configured. Call setAxiosInstance() before making API calls.",
    );
  }
  return _axiosInstance(config).then((res) => res as T);
};

export default customInstance;
