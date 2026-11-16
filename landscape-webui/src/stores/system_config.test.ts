import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPinia, setActivePinia } from "pinia";
import { useDnsConfigStore } from "./dns_config";
import { useTimeConfigStore } from "./time_config";
import {
  get_dns_config_edit,
  update_dns_config,
  get_time_config_edit,
  update_time_config,
} from "@/api/sys/config";

vi.mock("@/api/sys/config", () => ({
  get_dns_config_edit: vi.fn(),
  update_dns_config: vi.fn(),
  get_time_config_edit: vi.fn(),
  update_time_config: vi.fn(),
}));
beforeEach(() => {
  setActivePinia(createPinia());
  vi.resetAllMocks();
});

describe("DNS settings", () => {
  it("preserves all fields, including explicit false, when editing one field", async () => {
    vi.mocked(get_dns_config_edit).mockResolvedValue({
      dns: {
        cache_capacity: 4096,
        cache_ttl: 60,
        negative_cache_ttl: 10,
        doh_listen_port: 8443,
        doh_http_endpoint: "/custom",
        tcp_enabled: false,
      },
      hash: "original",
    });
    const store = useDnsConfigStore();
    await store.loadDnsConfig();
    store.cacheTtl = 120;
    await store.saveDnsConfig();
    expect(update_dns_config).toHaveBeenCalledWith({
      new_dns: {
        cache_capacity: 4096,
        cache_ttl: 120,
        negative_cache_ttl: 10,
        doh_listen_port: 8443,
        doh_http_endpoint: "/custom",
        tcp_enabled: false,
      },
      expected_hash: "original",
    });
  });
  it("omits cleared fields and reloads the hash after saving", async () => {
    vi.mocked(get_dns_config_edit)
      .mockResolvedValueOnce({ dns: { doh_listen_port: 8443 }, hash: "a" })
      .mockResolvedValueOnce({ dns: {}, hash: "b" });
    const store = useDnsConfigStore();
    await store.loadDnsConfig();
    store.dohListenPort = null;
    await store.saveDnsConfig();
    expect(
      JSON.parse(JSON.stringify(vi.mocked(update_dns_config).mock.calls[0][0])),
    ).toEqual({ new_dns: {}, expected_hash: "a" });
    expect(store.expectedHash).toBe("b");
  });
  it("blocks saving after a failed load", async () => {
    vi.mocked(get_dns_config_edit).mockRejectedValue(new Error("offline"));
    const store = useDnsConfigStore();
    await expect(store.loadDnsConfig()).rejects.toThrow();
    await store.saveDnsConfig();
    expect(update_dns_config).not.toHaveBeenCalled();
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
