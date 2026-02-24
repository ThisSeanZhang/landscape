import { resetCache } from "@landscape-router/types/api/route/route";

export async function reset_cache(): Promise<void> {
  await resetCache();
}
