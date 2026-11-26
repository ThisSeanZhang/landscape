import { createPinia, setActivePinia } from "pinia";
import { expect, it, vi } from "vitest";
import { get_capabilities } from "@/api/sys";
import { useCapabilityStore } from "./capability";

vi.mock("@/api/sys", () => ({ get_capabilities: vi.fn() }));

it("only exposes self-monitoring after the backend confirms mem-track", async () => {
  setActivePinia(createPinia());
  const store = useCapabilityStore();
  expect(store.HAS("mem_track")).toBe(false);
  vi.mocked(get_capabilities).mockRejectedValueOnce(new Error("offline"));
  await store.LOAD();
  expect(store.HAS("mem_track")).toBe(false);
  vi.mocked(get_capabilities).mockResolvedValueOnce(["metric_persistent"]);
  await store.LOAD();
  expect(store.HAS("mem_track")).toBe(false);
  store.RESET();
  vi.mocked(get_capabilities).mockResolvedValueOnce(["mem_track"]);
  await store.LOAD();
  expect(store.HAS("mem_track")).toBe(true);
  expect(store.HAS("metric_persistent")).toBe(false);
});
