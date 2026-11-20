import { effectScope, reactive, ref } from "vue";
import { afterEach, expect, it, vi } from "vitest";
import { useMetricAutoRefresh } from "./useMetricAutoRefresh";

const settings = reactive({ enable_interval: true, interval_time: 3000 });
const visibility = ref("visible");
vi.mock("@/stores/fetch_interval", () => ({
  useFetchIntervalStore: () => settings,
}));
vi.mock("@vueuse/core", () => ({ useDocumentVisibility: () => visibility }));

afterEach(() => vi.useRealTimers());

it("waits for the current sample, follows the refresh settings and stops on exit", async () => {
  vi.useFakeTimers();
  const scope = effectScope();
  const loading = ref(true);
  const liveTab = ref(true);
  const refresh = vi.fn(async () => {
    loading.value = true;
  });
  scope.run(() => useMetricAutoRefresh(refresh, loading, () => liveTab.value));

  await vi.advanceTimersByTimeAsync(6000);
  expect(refresh).not.toHaveBeenCalled();
  loading.value = false;
  await vi.advanceTimersByTimeAsync(3000);
  expect(refresh).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(6000);
  expect(refresh).toHaveBeenCalledTimes(1);

  loading.value = false;
  for (const pause of [
    () => {
      liveTab.value = false;
    },
    () => {
      visibility.value = "hidden";
    },
    () => {
      settings.enable_interval = false;
    },
  ]) {
    pause();
    await vi.advanceTimersByTimeAsync(3000);
    expect(refresh).toHaveBeenCalledTimes(1);
    liveTab.value = true;
    visibility.value = "visible";
    settings.enable_interval = true;
  }
  settings.interval_time = 500;
  await vi.advanceTimersByTimeAsync(500);
  expect(refresh).toHaveBeenCalledTimes(2);
  loading.value = false;
  scope.stop();
  await vi.advanceTimersByTimeAsync(6000);
  expect(refresh).toHaveBeenCalledTimes(2);
});
