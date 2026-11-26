import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPinia, setActivePinia } from "pinia";
import { useDnsConfigStore } from "./dns_config";
import { useMetricConfigStore } from "./metric_config";
import { useTimeConfigStore } from "./time_config";
import {
  getConnectMetricConfig,
  getDnsMetricConfig,
  updateDnsMetricConfig,
  updateConnectMetricConfig,
  getSelfMonitorConfig,
  getDnsCacheConfig,
  updateDnsCacheConfig,
  getDohConfig,
  updateDohConfig,
  get_time_config_edit,
  update_time_config,
} from "@/api/sys/config";

vi.mock("@/api/sys/config", () => ({
  getConnectMetricConfig: vi.fn(),
  getDnsMetricConfig: vi.fn(),
  updateConnectMetricConfig: vi.fn(),
  updateDnsMetricConfig: vi.fn(),
  getSelfMonitorConfig: vi.fn(),
  updateSelfMonitorConfig: vi.fn(),
  getDnsCacheConfig: vi.fn(),
  updateDnsCacheConfig: vi.fn(),
  getDohConfig: vi.fn(),
  updateDohConfig: vi.fn(),
  get_time_config_edit: vi.fn(),
  update_time_config: vi.fn(),
}));
beforeEach(() => {
  setActivePinia(createPinia());
  vi.resetAllMocks();
});

describe("DNS settings", () => {
  it("saves only the cache and preserves a pending DoH edit", async () => {
    vi.mocked(getDnsCacheConfig).mockResolvedValue({
      cache: { capacity: 4096, negative_ttl: 10 },
      hash: "cache",
    });
    vi.mocked(getDohConfig).mockResolvedValue({
      doh: { listen_port: 8443 },
      hash: "doh",
    });
    const store = useDnsConfigStore();
    await Promise.all([store.loadCache(), store.loadDoh()]);
    store.doh.httpEndpoint = "/pending";
    store.cache.ttl = 120;
    await store.saveCache();
    expect(updateDnsCacheConfig).toHaveBeenCalledWith({
      new_cache: { capacity: 4096, ttl: 120, negative_ttl: 10 },
      expected_hash: "cache",
    });
    expect(store.doh.httpEndpoint).toBe("/pending");
    expect(getDohConfig).toHaveBeenCalledTimes(1);
    expect(updateDohConfig).not.toHaveBeenCalled();
  });

  it("clears the DoH override and reloads only its hash", async () => {
    vi.mocked(getDohConfig)
      .mockResolvedValueOnce({ doh: { listen_port: 8443 }, hash: "a" })
      .mockResolvedValueOnce({ doh: {}, hash: "b" });
    const store = useDnsConfigStore();
    await store.loadDoh();
    store.doh.listenPort = null;
    await store.saveDoh();
    expect(
      JSON.parse(JSON.stringify(vi.mocked(updateDohConfig).mock.calls[0][0])),
    ).toEqual({
      new_doh: {},
      expected_hash: "a",
    });
    expect(store.doh.hash).toBe("b");
    expect(getDnsCacheConfig).not.toHaveBeenCalled();
  });

  it("lets cache save when DoH failed to load", async () => {
    vi.mocked(getDohConfig).mockRejectedValue(new Error("offline"));
    vi.mocked(getDnsCacheConfig).mockResolvedValue({ cache: {}, hash: "a" });
    const store = useDnsConfigStore();
    await expect(store.loadDoh()).rejects.toThrow();
    await store.loadCache();
    await store.saveDoh();
    await store.saveCache();
    expect(updateDohConfig).not.toHaveBeenCalled();
    expect(updateDnsCacheConfig).toHaveBeenCalledTimes(1);
  });
});

describe("time settings", () => {
  it("normalizes server lines and preserves false and zero", async () => {
    vi.mocked(get_time_config_edit).mockResolvedValue({
      time: {
        enabled: false,
        servers: ["old:123"],
        sync_interval_secs: 3600,
        timeout_secs: 3,
        step_threshold_ms: 0,
        samples_per_server: 3,
      },
      hash: "a",
    });
    const store = useTimeConfigStore();
    await store.loadTimeConfig();
    store.servers = " first:123 \n\n second:123 ";
    await store.saveTimeConfig();
    expect(update_time_config).toHaveBeenCalledWith({
      new_time: {
        enabled: false,
        servers: ["first:123", "second:123"],
        sync_interval_secs: 3600,
        timeout_secs: 3,
        step_threshold_ms: 0,
        samples_per_server: 3,
      },
      expected_hash: "a",
    });
  });
  it("omits unconfigured fields", async () => {
    vi.mocked(get_time_config_edit).mockResolvedValue({ time: {}, hash: "a" });
    const store = useTimeConfigStore();
    await store.loadTimeConfig();
    await store.saveTimeConfig();
    expect(
      JSON.parse(
        JSON.stringify(vi.mocked(update_time_config).mock.calls[0][0]),
      ),
    ).toEqual({ new_time: {}, expected_hash: "a" });
  });
  it("preserves input and hash on conflict, and releases saving state", async () => {
    vi.mocked(get_time_config_edit).mockResolvedValue({ time: {}, hash: "a" });
    vi.mocked(update_time_config).mockRejectedValue({
      response: { status: 409 },
    });
    const store = useTimeConfigStore();
    await store.loadTimeConfig();
    store.timeoutSecs = 10;
    await expect(store.saveTimeConfig()).rejects.toBeDefined();
    expect(store.timeoutSecs).toBe(10);
    expect(store.expectedHash).toBe("a");
    expect(store.saving).toBe(false);
    expect(get_time_config_edit).toHaveBeenCalledTimes(1);
  });
  it("prevents duplicate saves", async () => {
    vi.mocked(get_time_config_edit).mockResolvedValue({ time: {}, hash: "a" });
    let finish!: () => void;
    vi.mocked(update_time_config).mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    );
    const store = useTimeConfigStore();
    await store.loadTimeConfig();
    const pending = store.saveTimeConfig();
    await store.saveTimeConfig();
    expect(update_time_config).toHaveBeenCalledTimes(1);
    finish();
    await pending;
    expect(store.saving).toBe(false);
  });
});

describe("metric settings", () => {
  it("saves DNS without reloading pending connection settings or fetching self-monitor", async () => {
    vi.mocked(getConnectMetricConfig).mockResolvedValue({
      config: { store: { backend: "memory" } },
      hash: "connect",
    });
    vi.mocked(getDnsMetricConfig).mockResolvedValue({
      config: { store: {} },
      hash: "dns",
    });
    const store = useMetricConfigStore();
    await Promise.all([store.connect.load(), store.dns.load()]);
    store.connect.config.write_batch_size = 123;
    store.dns.config.enabled = false;
    await store.dns.save();
    expect(updateDnsMetricConfig).toHaveBeenCalledWith({
      config: { enabled: false, store: {} },
      expected_hash: "dns",
    });
    expect(getConnectMetricConfig).toHaveBeenCalledTimes(1);
    expect(updateConnectMetricConfig).not.toHaveBeenCalled();
    expect(store.connect.config.write_batch_size).toBe(123);
    expect(getSelfMonitorConfig).not.toHaveBeenCalled();
  });
});
