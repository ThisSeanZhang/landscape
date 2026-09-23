import { NetDev, DevStateType } from "@/lib/dev";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/api/network", () => ({
  ifaces: async () => [],
}));

vi.stubGlobal("localStorage", {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
});

const {
  get_visible_devices,
  filter_link_managed_devices,
  estimate_node_height,
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

describe("get_visible_devices", () => {
  it("始终隐藏 Loopback 设备", () => {
    const visible = get_visible_devices(
      [
        net_dev({ name: "lo", index: 1, dev_type: "Loopback" }),
        net_dev({ name: "eth0", index: 2 }),
      ],
      false,
    );

    expect(visible.map((each) => each.name)).toEqual(["eth0"]);
  });

  it("hide_down 时隐藏 Down 的真实网卡", () => {
    const visible = get_visible_devices(
      [
        net_dev({
          name: "eth1",
          index: 3,
          dev_status: { t: DevStateType.Down },
        }),
        net_dev({ name: "eth0", index: 2 }),
      ],
      true,
    );

    expect(visible.map((each) => each.name)).toEqual(["eth0"]);
  });

  it("hide_down 关闭时保留 Down 网卡", () => {
    const devs = [
      net_dev({ name: "eth1", index: 3, dev_status: { t: DevStateType.Down } }),
      net_dev({ name: "eth0", index: 2 }),
    ];

    expect(get_visible_devices(devs, false)).toHaveLength(2);
  });

  it("按 zone 分组且 bridge 排在最前", () => {
    const visible = get_visible_devices(
      [
        net_dev({ name: "lan0", index: 4, zone_type: IfaceZoneType.lan }),
        net_dev({
          name: "br-lan",
          index: 5,
          dev_kind: "bridge",
          zone_type: IfaceZoneType.lan,
        }),
        net_dev({ name: "wan0", index: 2 }),
      ],
      false,
    );

    expect(visible.map((each) => each.name)).toEqual([
      "wan0",
      "br-lan",
      "lan0",
    ]);
  });
});

describe("filter_link_managed_devices", () => {
  it("隐藏被 pppd link 托管的 ppp 设备", () => {
    const devs = [
      net_dev({ name: "eth0", index: 2 }),
      net_dev({ name: "ppp-eth0-abc", index: 6, dev_type: "ppp" }),
    ];

    const visible = filter_link_managed_devices(
      devs,
      new Set(["ppp-eth0-abc"]),
    );

    expect(visible.map((each) => each.name)).toEqual(["eth0"]);
  });

  it("未被托管的 ppp 设备仍然展示", () => {
    const devs = [
      net_dev({ name: "eth0", index: 2 }),
      net_dev({ name: "ppp0", index: 7, dev_type: "ppp" }),
    ];

    const visible = filter_link_managed_devices(devs, new Set());

    expect(visible.map((each) => each.name)).toEqual(["eth0", "ppp0"]);
  });
});

describe("estimate_node_height", () => {
  const wan_link = (iface: string, kind: string) =>
    ({
      attach_iface_name: iface,
      kind: { t: kind },
    }) as any;

  it("非 WAN 设备使用固定高度", () => {
    const lan = net_dev({
      name: "lan0",
      index: 4,
      zone_type: IfaceZoneType.lan,
    });

    expect(estimate_node_height(lan, new Map())).toBe(136);
  });

  it("WAN 设备高度随 link 数量增长", () => {
    const wan = net_dev({ name: "eth0", index: 2 });
    const links = new Map([[wan.name, [wan_link("eth0", "ethernet")]]]);

    const zero = estimate_node_height(wan, new Map());
    const one = estimate_node_height(wan, links);
    const two = estimate_node_height(
      wan,
      new Map([
        [wan.name, [wan_link("eth0", "ethernet"), wan_link("eth0", "pppd")]],
      ]),
    );

    expect(zero).toBe(136);
    expect(one).toBe(zero + 44);
    expect(two).toBe(zero + 88);
  });

  it("link 满员时 WAN 高度仍包含已有 link 行", () => {
    const wan = net_dev({ name: "eth0", index: 2 });
    const links = new Map([
      [
        wan.name,
        [wan_link("eth0", "ethernet"), wan_link("eth0", "pppoe_native")],
      ],
    ]);

    const height = estimate_node_height(wan, links);

    expect(height).toBe(136 + 2 * 44);
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

    const { positions } = compute_layout(
      [member, wan, core],
      new Map(),
      new Map(),
    );

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

    const { positions } = compute_layout(
      [wan0, wan1, core],
      new Map(),
      new Map(),
    );

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

    const estimated = compute_layout([wan, core], new Map(), new Map());
    const measured = compute_layout(
      [wan, core],
      new Map(),
      new Map([["1", 400]]),
    );

    expect(measured.size.height).toBeGreaterThan(estimated.size.height);
    expect(measured.size.height).toBeGreaterThanOrEqual(400);
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

    const { positions } = compute_layout([orphan, core], new Map(), new Map());

    expect(positions.get("9")).toBeDefined();
    expect(positions.get("2")).toBeDefined();
  });
});
