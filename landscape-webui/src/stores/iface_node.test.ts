import { NetDev, DevStateType } from "@/lib/dev";
import { default_pppd_link, WanLink } from "@/lib/wan_link";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/api/network", () => ({
  ifaces: async () => [],
}));

vi.mock("@/api/service_wan_link", () => ({
  get_all_wan_links: async () => [],
}));

vi.stubGlobal("localStorage", {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
});

const {
  get_visible_devices,
  merge_pppd_placeholders,
  stable_negative_hash,
  compute_layout,
} = await import("@/stores/iface_node");

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
    controller_id: number;
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

function pppd_link(ppp_iface_name: string, attach = "eth0"): WanLink {
  const link = default_pppd_link(attach);
  link.kind = {
    t: "pppd",
    ppp_iface_name,
    peer_id: "",
    password: "",
    ac: null,
    plugin: "rp_pppoe",
  };
  return link;
}

describe("merge_pppd_placeholders", () => {
  it("为未拨通的配置生成虚拟占位网卡", () => {
    const devs = [net_dev({ name: "eth0", index: 2 })];
    const config = pppd_link("ppp-eth0-abc");
    const merged = merge_pppd_placeholders(devs, [config]);

    expect(merged).toHaveLength(2);
    const placeholder = merged.find((each) => each.name === "ppp-eth0-abc");
    expect(placeholder).toBeDefined();
    expect(placeholder!.virtual).toBe(true);
    expect(placeholder!.zone_type).toBe(IfaceZoneType.wan);
    expect(placeholder!.dev_type).toBe("ppp");
    expect(placeholder!.wan_link).toBe(config);
    expect(placeholder!.index).toBeLessThan(0);
    expect(placeholder!.controller_id).toBeUndefined();
    expect(placeholder!.has_target_hook()).toBe(false);
    expect(placeholder!.has_source_hook()).toBe(false);
  });

  it("拨通后的配置挂载到真实网卡且不生成占位卡", () => {
    const live = net_dev({ name: "ppp-eth0-abc", index: 5, dev_type: "ppp" });
    const config = pppd_link("ppp-eth0-abc");
    const merged = merge_pppd_placeholders([live], [config]);

    expect(merged).toHaveLength(1);
    expect(merged[0].wan_link).toBe(config);
    expect(merged[0].virtual).toBe(false);
  });

  it("占位卡 index 跨刷新保持稳定且不与真实 ifindex 冲突", () => {
    const devs = [net_dev({ name: "eth0", index: 1 })];
    const config = pppd_link("ppp-eth0-abc");

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
      [pppd_link("ppp-x", "eth1")],
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
      [pppd_link("ppp-x", "eth1")],
    )[0];

    const visible = get_visible_devices([real_down, virtual_down], false);
    expect(visible).toHaveLength(2);
  });
});

describe("compute_layout", () => {
  it("三列结构：WAN 在左、core 居中、bridge 成员在右", () => {
    const wan = net_dev({ name: "wan0", index: 1 });
    const core = net_dev({
      name: "br-lan",
      index: 2,
      dev_kind: "bridge",
      zone_type: IfaceZoneType.lan,
    });
    const member = net_dev({
      name: "eth1",
      index: 3,
      zone_type: IfaceZoneType.lan,
      controller_id: 2,
    });

    const { positions } = compute_layout([member, wan, core], new Map());

    const wan_x = positions.get("1")!.x;
    const core_x = positions.get("2")!.x;
    const member_x = positions.get("3")!.x;

    expect(wan_x).toBeLessThan(core_x);
    expect(core_x).toBeLessThan(member_x);
  });

  it("同列节点纵向不重叠", () => {
    const wan0 = net_dev({ name: "wan0", index: 1 });
    const wan1 = net_dev({ name: "wan1", index: 2 });
    const core = net_dev({
      name: "br-lan",
      index: 3,
      zone_type: IfaceZoneType.lan,
    });

    const { positions } = compute_layout([wan0, wan1, core], new Map());

    const top = positions.get("1")!;
    const bottom = positions.get("2")!;
    const first = top.y <= bottom.y ? top : bottom;
    const second = top.y <= bottom.y ? bottom : top;

    expect(second.y - first.y).toBeGreaterThanOrEqual(136);
  });

  it("WAN 根的成员对齐到第三列（而非中列）", () => {
    const wan = net_dev({ name: "wan0", index: 1 });
    const core = net_dev({
      name: "br-lan",
      index: 2,
      zone_type: IfaceZoneType.lan,
    });
    const core_member = net_dev({
      name: "eth1",
      index: 3,
      zone_type: IfaceZoneType.lan,
      controller_id: 2,
    });
    const wan_member = net_dev({
      name: "eth9",
      index: 4,
      controller_id: 1,
    });

    const { positions } = compute_layout(
      [wan, core, core_member, wan_member],
      new Map(),
    );

    const member_x = positions.get("3")!.x;
    const wan_member_x = positions.get("4")!.x;

    expect(Math.abs(member_x - wan_member_x)).toBeLessThan(60);
  });

  it("同列卡片间隔一致（三张 WAN 卡）", () => {
    const wan0 = net_dev({ name: "wan0", index: 1 });
    const wan1 = net_dev({ name: "wan1", index: 2 });
    const wan2 = net_dev({ name: "wan2", index: 3 });
    const core = net_dev({
      name: "br-lan",
      index: 4,
      zone_type: IfaceZoneType.lan,
    });
    const member = net_dev({
      name: "eth5",
      index: 5,
      zone_type: IfaceZoneType.lan,
      controller_id: 4,
    });

    const { positions } = compute_layout(
      [wan0, wan1, wan2, core, member],
      new Map(),
    );

    const column = [
      positions.get("1")!,
      positions.get("2")!,
      positions.get("3")!,
    ].sort((a, b) => a.y - b.y);
    const gap_1_2 = column[1].y - (column[0].y + 136);
    const gap_2_3 = column[2].y - (column[1].y + 136);

    expect(gap_1_2).toBe(gap_2_3);
    expect(gap_1_2).toBeGreaterThanOrEqual(24);
  });

  it("实测高度参与布局且图高随之增长", () => {
    const wan = net_dev({ name: "wan0", index: 1 });
    const core = net_dev({
      name: "br-lan",
      index: 2,
      zone_type: IfaceZoneType.lan,
    });

    const estimated = compute_layout([wan, core], new Map());
    const measured = compute_layout([wan, core], new Map([["1", 400]]));

    expect(measured.size.height).toBeGreaterThan(estimated.size.height);
    expect(measured.size.height).toBeGreaterThanOrEqual(400);
  });

  it("列内顺序跟随设备排序（不颠倒）", () => {
    const wan0 = net_dev({ name: "wan0", index: 8 });
    const wan1 = net_dev({ name: "wan1", index: 9 });
    const wan2 = net_dev({ name: "wan2", index: 10 });
    const brA = net_dev({
      name: "br-a",
      index: 3,
      dev_kind: "bridge",
      zone_type: IfaceZoneType.lan,
    });
    const brB = net_dev({
      name: "br-b",
      index: 4,
      dev_kind: "bridge",
      zone_type: IfaceZoneType.lan,
    });

    const { positions } = compute_layout(
      [wan0, wan1, wan2, brA, brB],
      new Map(),
    );

    expect(positions.get("8")!.y).toBeLessThan(positions.get("9")!.y);
    expect(positions.get("9")!.y).toBeLessThan(positions.get("10")!.y);
    expect(positions.get("3")!.y).toBeLessThan(positions.get("4")!.y);
  });

  it("最后一列按 controller 分组排序（组序跟随 controller 列序）", () => {
    const wan = net_dev({ name: "wan0", index: 8 });
    const brA = net_dev({
      name: "br-a",
      index: 3,
      dev_kind: "bridge",
      zone_type: IfaceZoneType.lan,
    });
    const brB = net_dev({
      name: "br-b",
      index: 4,
      dev_kind: "bridge",
      zone_type: IfaceZoneType.lan,
    });
    const eth1 = net_dev({
      name: "eth1",
      index: 6,
      zone_type: IfaceZoneType.lan,
      controller_id: 4,
    });
    const eth2 = net_dev({
      name: "eth2",
      index: 7,
      zone_type: IfaceZoneType.lan,
      controller_id: 3,
    });
    const eth3 = net_dev({
      name: "eth3",
      index: 9,
      zone_type: IfaceZoneType.lan,
      controller_id: 4,
    });

    const { positions } = compute_layout(
      [wan, brA, brB, eth1, eth2, eth3],
      new Map(),
    );

    // br-a 在 br-b 上方，因此其成员 eth2 排在 br-b 的 eth1/eth3 之前，
    // 即使名称顺序交错。
    const ys = [eth2, eth1, eth3].map(
      (each) => positions.get(`${each.index}`)!.y,
    );
    expect(ys[0]).toBeLessThan(ys[1]);
    expect(ys[1]).toBeLessThan(ys[2]);
  });

  it("controller 缺失的设备不产生边且不崩溃", () => {
    const orphan = net_dev({
      name: "eth9",
      index: 9,
      zone_type: IfaceZoneType.lan,
      controller_id: 99,
    });
    const core = net_dev({
      name: "br-lan",
      index: 2,
      zone_type: IfaceZoneType.lan,
    });

    const { positions } = compute_layout([orphan, core], new Map());

    expect(positions.get("9")).toBeDefined();
    expect(positions.get("2")).toBeDefined();
  });
});
