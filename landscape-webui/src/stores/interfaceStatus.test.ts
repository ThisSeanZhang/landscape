import { createPinia, setActivePinia } from "pinia";
import { expect, it, vi } from "vitest";
import type { ServiceStatus } from "@/lib/services";
import { defineInterfaceStatusStore } from "./interfaceStatus";

it("updates existing interface lookups while keeping services independent", async () => {
  setActivePinia(createPinia());
  const fetchStatus = vi.fn<() => Promise<Map<string, ServiceStatus>>>();
  const lan = defineInterfaceStatusStore("lan", fetchStatus)();
  const wan = defineInterfaceStatusStore("wan", async () => new Map())();
  const lanStatus = lan.GET_STATUS_BY_IFACE_NAME("eth0");
  const wanStatus = wan.GET_STATUS_BY_IFACE_NAME("eth0");

  fetchStatus.mockResolvedValueOnce(new Map([["eth0", { t: "running" }]]));
  await lan.UPDATE_INFO();
  expect(lanStatus.value?.t).toBe("running");
  expect(wanStatus.value).toBeUndefined();

  fetchStatus.mockResolvedValueOnce(new Map());
  await lan.UPDATE_INFO();
  expect(lanStatus.value).toBeUndefined();
});
