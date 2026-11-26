import { ref, watch } from "vue";

export function usePolling(
  refresh: (isCurrent: () => boolean) => Promise<void>,
) {
  const enable_interval = ref(true);
  const interval_time = ref(3000);
  const error_message = ref<string>();
  let resetCountdown: (() => void) | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let generation = 0;
  let running = false;

  function active() {
    return (
      resetCountdown !== undefined && enable_interval.value && !document.hidden
    );
  }

  async function run() {
    if (running || !active()) return;
    running = true;
    error_message.value = undefined;
    const current = generation;
    try {
      await refresh(() => current === generation);
    } catch (error) {
      if (current === generation) {
        error_message.value =
          error instanceof Error ? error.message : String(error);
        enable_interval.value = false;
      }
    } finally {
      running = false;
      if (active()) {
        if (current === generation) {
          resetCountdown?.();
          timer = setTimeout(run, interval_time.value);
        } else {
          // A new session or refresh request arrived while the old one was finishing.
          void run();
        }
      }
    }
  }

  function restart() {
    generation++;
    clearTimeout(timer);
    void run();
  }

  watch(enable_interval, restart, { flush: "sync" });

  function refreshNow() {
    if (enable_interval.value) restart();
    else enable_interval.value = true;
  }

  function start(onCountdown: () => void) {
    resetCountdown = onCountdown;
    document.addEventListener("visibilitychange", restart);
    refreshNow();
  }

  function stop() {
    resetCountdown = undefined;
    document.removeEventListener("visibilitychange", restart);
    restart();
  }

  return {
    enable_interval,
    interval_time,
    error_message,
    start,
    stop,
    refreshNow,
  };
}
