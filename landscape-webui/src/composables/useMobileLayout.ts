import { useMediaQuery } from "@vueuse/core";

export function useMobileLayout() {
  return useMediaQuery("(max-width: 768px)");
}
