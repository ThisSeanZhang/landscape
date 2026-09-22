import { NetDev, DevStateType } from "@/lib/dev";
import { PPPDServiceConfig } from "@/lib/pppd";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/api/network", () => ({
  ifaces: async () => [],
}));

vi.mock("@/api/service_pppd", () => ({
  get_all_iface_pppd_config: async () => [],
}));

vi.stubGlobal("localStorage", {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
});

const { get_visible_devices, merge_pppd_placeholders, stable_negative_hash } =
  await import("@/stores/iface_node");

function net_dev(
  obj: Partial<{
    name: string;
    index: number;
    dev_type: string;
    dev_kind: string;
    dev_status: { t: DevStateType };
    carrier: boolean;
    zone_type: IfaceZoneType;
    enable_in_boot: boolean;
  }> & { name: string; index: number },
): NetDev {
  return new NetDev({
    dev_type: "ethernet",
    dev_kind: "ethernet",
    dev_status: { t: DevStateType.Up },
    carrier: true,
    zone_type: IfaceZoneType.wan,
    enable_in_boot: true,
    ...obj,
  });
}

function pppd_config(iface_name: string, attach = "eth0"): PPPDServiceConfig {
  return new PPPDServiceConfig({ attach_iface_name: attach, iface_name });
}

describe("merge_pppd_placeholders", () => {
  it("为未拨通的配置生成虚拟占位网卡", () => {
    const devs = [net_dev({ name: "eth0", index: 2 })];
    const config = pppd_config("ppp-eth0-abc");
    const merged = merge_pppd_placeholders(devs, [config]);

    expect(merged).toHaveLength(2);
    const placeholder = merged.find((each) => each.name === "ppp-eth0-abc");
    expect(placeholder).toBeDefined();
    expect(placeholder!.virtual).toBe(true);
    expect(placeholder!.zone_type).toBe(IfaceZoneType.wan);
    expect(placeholder!.dev_type).toBe("ppp");
    expect(placeholder!.pppd_config).toBe(config);
    expect(placeholder!.index).toBeLessThan(0);
    expect(placeholder!.controller_id).toBeUndefined();
    expect(placeholder!.has_target_hook()).toBe(false);
    expect(placeholder!.has_source_hook()).toBe(false);
  });

  it("拨通后的配置挂载到真实网卡且不生成占位卡", () => {
    const live = net_dev({ name: "ppp-eth0-abc", index: 5, dev_type: "ppp" });
    const config = pppd_config("ppp-eth0-abc");
    const merged = merge_pppd_placeholders([live], [config]);

    expect(merged).toHaveLength(1);
    expect(merged[0].pppd_config).toBe(config);
    expect(merged[0].virtual).toBe(false);
  });

  it("占位卡 index 跨刷新保持稳定且不与真实 ifindex 冲突", () => {
    const devs = [net_dev({ name: "eth0", index: 1 })];
    const config = pppd_config("ppp-eth0-abc");

    const first = merge_pppd_placeholders(devs, [config]);
    const second = merge_pppd_placeholders(devs, [config]);
    const first_index = first.find((each) => each.virtual)!.index;
    const second_index = second.find((each) => each.virtual)!.index;

    expect(first_index).toBe(second_index);
    expect(first_index).toBeLessThan(0);
  });
});

describe("stable_negative_hash", () => {
  it("同名结果确定且恒为负数", () => {
    const first = stable_negative_hash("ppp-a", new Set());
    const second = stable_negative_hash("ppp-a", new Set());

    expect(first).toBe(second);
    expect(first).toBeLessThan(0);
  });

  it("哈希碰撞时递减避让已占用的 index", () => {
    const base = stable_negative_hash("ppp-a", new Set());
    const avoided = stable_negative_hash("ppp-a", new Set([base]));

    expect(avoided).toBe(base - 1);

    const used = new Set<number>();
    const first = stable_negative_hash("ppp-a", used);
    const second = stable_negative_hash("ppp-a", used);
    expect(second).not.toBe(first);
  });
});

describe("get_visible_devices", () => {
  it("hide_down 隐藏真实 Down 网卡但保留虚拟占位卡", () => {
    const real_down = net_dev({
      name: "eth1",
      index: 3,
      dev_status: { t: DevStateType.Down },
    });
    const virtual_down = merge_pppd_placeholders(
      [],
      [pppd_config("ppp-x", "eth1")],
    )[0];
    expect(virtual_down.dev_status.t).toBe(DevStateType.Down);

    const visible = get_visible_devices([real_down, virtual_down], true);
    expect(visible.map((each) => each.name)).toEqual(["ppp-x"]);
  });

  it("hide_down 关闭时两者都保留", () => {
    const real_down = net_dev({
      name: "eth1",
      index: 3,
      dev_status: { t: DevStateType.Down },
    });
    const virtual_down = merge_pppd_placeholders(
      [],
      [pppd_config("ppp-x", "eth1")],
    )[0];

    const visible = get_visible_devices([real_down, virtual_down], false);
    expect(visible).toHaveLength(2);
  });
});
