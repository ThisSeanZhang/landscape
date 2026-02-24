import { resetCache } from "landscape-types/api/route/route";

export async function reset_cache(): Promise<void> {
  await resetCache();
}
