import { onScopeDispose, ref } from "vue";

export function useLatestHistoryQuery() {
  const loading = ref(false);
  const failed = ref(false);
  const hasResult = ref(false);
  let latest = 0;

  function invalidate() {
    latest++;
    loading.value = false;
  }
  onScopeDispose(invalidate);

  async function run<T>(load: () => Promise<T>, publish: (result: T) => void) {
    const request = ++latest;
    loading.value = true;
    try {
      const result = await load();
      if (latest !== request) return;
      failed.value = false;
      hasResult.value = true;
      publish(result);
    } catch {
      if (latest === request) failed.value = true;
    } finally {
      if (latest === request) loading.value = false;
    }
  }

  return { loading, failed, hasResult, invalidate, run };
}
