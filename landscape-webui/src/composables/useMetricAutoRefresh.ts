import { useDocumentVisibility } from "@vueuse/core";
import { watchSyncEffect, type Ref } from "vue";
import { useFetchIntervalStore } from "@/stores/fetch_interval";

export function useMetricAutoRefresh(
  refresh: () => Promise<unknown>,
  loading: Readonly<Ref<boolean>>,
  active: () => boolean = () => true,
) {
  const settings = useFetchIntervalStore();
  const visibility = useDocumentVisibility();

  // A manual or automatic request clears the timer. Start the next interval
  // once its loading flag drops, while this view is still visible.
  watchSyncEffect((onCleanup) => {
    if (
      !active() ||
      !settings.enable_interval ||
      visibility.value !== "visible" ||
      loading.value
    )
      return;
    const timer = setTimeout(() => void refresh(), settings.interval_time);
    onCleanup(() => clearTimeout(timer));
  });
}
