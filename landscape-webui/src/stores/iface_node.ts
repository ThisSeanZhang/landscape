import { ifaces } from "@/api/network";
import { DevStateType, NetDev } from "@/lib/dev";
import {
  IfaceZoneType,
  type WanLinkConfig,
} from "@landscape-router/types/api/schemas";
import { useWanLinkStore } from "@/stores/wan_link";
import * as dagre from "@dagrejs/dagre";
import { defineStore } from "pinia";
import { computed, ref, watch } from "vue";

interface IfaceOption {
  label: string;
  value: string;
  ifindex: number;
}

/** Real rendered card width (must match FlowNode). */
const NODE_WIDTH = 235;
/** Base card height estimate used before the DOM is measured. */
const NODE_HEIGHT = 136;
/** One link row (two lines incl. service chips) + row gap. */
const WAN_LINK_ROW_HEIGHT = 44;
/** Vertical gap between stacked cards: tight rhythm within a column (0.2 × card height). */
const NODE_SEP = Math.round(NODE_HEIGHT * 0.2);
/** Horizontal gap between adjacent columns: golden ratio (0.618) of card width. */
const COLUMN_GAP = NODE_WIDTH * 0.618;
/** Top margin of the graph. */
const GRAPH_TOP_MARGIN = 72;
const MIN_GRAPH_WIDTH = 940;
const MAX_GRAPH_WIDTH = 1480;

function sort_devices(devs: NetDev[]) {
  const zone_rank = (zone: IfaceZoneType) => {
    switch (zone) {
      case IfaceZoneType.wan:
        return 0;
      case IfaceZoneType.lan:
        return 1;
      default:
        return 2;
    }
  };

  return [...devs].sort((left, right) => {
    const zone_diff = zone_rank(left.zone_type) - zone_rank(right.zone_type);
    if (zone_diff !== 0) {
      return zone_diff;
    }

    if (left.dev_kind === "bridge" && right.dev_kind !== "bridge") {
      return -1;
    }
    if (left.dev_kind !== "bridge" && right.dev_kind === "bridge") {
      return 1;
    }

    return left.name.localeCompare(right.name, undefined, {
      numeric: true,
      sensitivity: "base",
    });
  });
}

export function get_visible_devices(devs: NetDev[], hide_down: boolean) {
  return sort_devices(
    devs.filter((each) => {
      if (each.dev_type === "Loopback") {
        return false;
      }

      if (hide_down && each.dev_status.t === DevStateType.Down) {
        return false;
      }

      return true;
    }),
  );
}

/** Hide kernel devices fully owned by a WAN link (e.g. pppd's ppp iface). */
export function filter_link_managed_devices(
  devs: NetDev[],
  managed_ifaces: Set<string>,
) {
  return devs.filter((each) => !managed_ifaces.has(each.name));
}

function create_layout_signature(
  devs: NetDev[],
  width: number,
  links: WanLinkConfig[],
) {
  return JSON.stringify({
    width,
    devices: devs.map((each) => ({
      index: each.index,
      controller_id: each.controller_id ?? null,
      zone_type: each.zone_type,
      dev_kind: each.dev_kind ?? "",
      name: each.name,
    })),
    wan_links: links.map((link) => ({
      iface: link.attach_iface_name,
      kind: link.kind?.t ?? "",
    })),
  });
}

/**
 * WAN cards stack link rows inside the card, so their real height grows with
 * the link count. Real DOM height ≈ 112 + 44·n (row = two lines incl. service
 * chips); the estimate stays intentionally close so the first frame (before
 * measured heights arrive) shows near-constant gaps.
 */
export function estimate_node_height(
  dev: NetDev,
  links_by_iface: Map<string, WanLinkConfig[]>,
): number {
  if (dev.zone_type !== IfaceZoneType.wan) {
    return NODE_HEIGHT;
  }

  const link_count = links_by_iface.get(dev.name)?.length ?? 0;
  return NODE_HEIGHT + link_count * WAN_LINK_ROW_HEIGHT;
}

export interface LayoutResult {
  /** Node id (ifindex) → top-left position, normalized to (0, 0). */
  positions: Map<string, { x: number; y: number }>;
  size: { width: number; height: number };
}

/**
 * Layered layout via dagre (`rankdir: LR`): WAN roots in the left column,
 * core roots (bridges / router ifaces) in the middle, bridge members on the
 * right. Invisible edges from WAN roots to core roots force the rank order.
 */
export function compute_layout(
  devs: NetDev[],
  links_by_iface: Map<string, WanLinkConfig[]>,
  heights: Map<string, number>,
): LayoutResult {
  const graph = new dagre.graphlib.Graph();
  graph.setGraph({
    rankdir: "LR",
    nodesep: NODE_SEP,
    edgesep: 16,
    marginx: 0,
    marginy: 0,
  });
  graph.setDefaultEdgeLabel(() => ({}));

  const device_map = new Map(devs.map((each) => [each.index, each]));
  const id = (index: number) => `${index}`;

  for (const each of devs) {
    const height =
      heights.get(id(each.index)) ?? estimate_node_height(each, links_by_iface);
    graph.setNode(id(each.index), { width: NODE_WIDTH, height });
  }

  const is_root = (each: NetDev) =>
    each.controller_id === undefined || !device_map.has(each.controller_id);

  for (const each of devs) {
    if (each.controller_id === undefined) {
      continue;
    }
    if (!device_map.has(each.controller_id)) {
      continue;
    }

    const controller = device_map.get(each.controller_id)!;
    // Members of a WAN root must land in the third column (rank 2), aligned
    // with the core root members, instead of overlapping the middle column.
    const minlen =
      controller.zone_type === IfaceZoneType.wan && is_root(controller) ? 2 : 1;
    graph.setEdge(id(each.controller_id), id(each.index), {
      minlen,
      weight: 1,
    });
  }

  const wan_roots = devs.filter(
    (each) => each.zone_type === IfaceZoneType.wan && is_root(each),
  );
  const core_roots = devs.filter(
    (each) => each.zone_type !== IfaceZoneType.wan && is_root(each),
  );

  for (const wan of wan_roots) {
    for (const core of core_roots) {
      graph.setEdge(id(wan.index), id(core.index), { weight: 0 });
    }
  }

  dagre.layout(graph);

  interface LayoutItem {
    x: number;
    y: number;
    width: number;
    height: number;
    rank: number;
  }

  const items = new Map<string, LayoutItem>();
  for (const each of devs) {
    const node = graph.node(id(each.index));
    items.set(id(each.index), {
      x: node.x,
      y: node.y,
      width: node.width,
      height: node.height,
      rank: node.rank ?? 0,
    });
  }

  // dagre 会把节点往邻居中位线方向拉（隐形边/子节点），导致同列间隔不均。
  // 同一 rank（同一列）内改为均匀堆叠：间隔恒为 NODE_SEP，整组保持原中点。
  // X 方向同样按列规整：相邻列间固定间隔 COLUMN_GAP，与 dagre 的 ranksep 无关。
  const by_rank = new Map<number, LayoutItem[]>();
  for (const item of items.values()) {
    const group = by_rank.get(item.rank) ?? [];
    group.push(item);
    by_rank.set(item.rank, group);
  }

  const ranks = [...by_rank.keys()].sort((left, right) => left - right);
  const column_stride = NODE_WIDTH + COLUMN_GAP;
  ranks.forEach((rank, order) => {
    const x_center = (order * column_stride + NODE_WIDTH / 2) as number;
    for (const item of by_rank.get(rank)!) {
      item.x = x_center;
    }
  });

  for (const group of by_rank.values()) {
    if (group.length < 2) {
      continue;
    }

    group.sort((left, right) => left.y - right.y);
    const top = Math.min(...group.map((item) => item.y - item.height / 2));
    const bottom = Math.max(...group.map((item) => item.y + item.height / 2));
    const total =
      group.reduce((sum, item) => sum + item.height, 0) +
      NODE_SEP * (group.length - 1);

    let cursor = (top + bottom) / 2 - total / 2;
    for (const item of group) {
      item.y = cursor + item.height / 2;
      cursor += item.height + NODE_SEP;
    }
  }

  const positions = new Map<string, { x: number; y: number }>();
  let min_x = Infinity;
  let min_y = Infinity;
  let max_x = -Infinity;
  let max_y = -Infinity;

  for (const [key, item] of items) {
    const x = item.x - item.width / 2;
    const y = item.y - item.height / 2;
    positions.set(key, { x, y });
    min_x = Math.min(min_x, x);
    min_y = Math.min(min_y, y);
    max_x = Math.max(max_x, x + item.width);
    max_y = Math.max(max_y, y + item.height);
  }

  for (const position of positions.values()) {
    position.x -= min_x;
    position.y -= min_y;
  }

  return {
    positions,
    size: { width: max_x - min_x, height: max_y - min_y },
  };
}

export const useIfaceNodeStore = defineStore(
  "iface_node",
  () => {
    const wanLinkStore = useWanLinkStore();
    const net_devs = ref<NetDev[]>([]);

    const hide_down_dev = ref(false);
    const view_locked = ref(true);

    const nodes = ref<any[]>([]);
    const edges = ref<any[]>([]);

    const bridges = ref<IfaceOption[]>([]);
    const eths = ref<IfaceOption[]>([]);

    const layout_width = ref(1200);
    const panel_reserved_width = ref(0);
    const node_call_back = ref<(() => void) | undefined>();
    const last_layout_signature = ref<string | null>(null);

    /** Measured DOM heights per node id, fed back from vue-flow. */
    const node_heights = ref<Map<string, number>>(new Map());
    const heights_settled = ref(false);

    const visible_net_devs = computed(() =>
      filter_link_managed_devices(
        get_visible_devices(net_devs.value, hide_down_dev.value),
        wanLinkStore.linkManagedIfaces,
      ),
    );

    watch(
      [
        visible_net_devs,
        layout_width,
        panel_reserved_width,
        () => wanLinkStore.byAttachIface,
        node_heights,
      ],
      ([new_value]) => {
        const new_bridges: IfaceOption[] = [];
        const new_eths: IfaceOption[] = [];

        for (const each of new_value) {
          if (each.dev_kind === "bridge") {
            new_bridges.push({
              label: each.name,
              value: each.name,
              ifindex: each.index,
            });
          } else if (each.zone_type !== IfaceZoneType.wan) {
            new_eths.push({
              label: each.name,
              value: each.name,
              ifindex: each.index,
            });
          }
        }

        const { positions, size } = compute_layout(
          new_value,
          wanLinkStore.byAttachIface,
          node_heights.value,
        );

        const available_width = Math.max(
          layout_width.value - panel_reserved_width.value,
          MIN_GRAPH_WIDTH,
        );
        const graph_width = Math.min(available_width, MAX_GRAPH_WIDTH);
        const graph_offset_x = Math.max(
          Math.round((available_width - graph_width) / 2),
          0,
        );
        const offset_x =
          graph_offset_x +
          Math.max(Math.round((graph_width - size.width) / 2), 0);

        const tmp_nodes: any[] = [];
        for (const each of new_value) {
          const position = positions.get(`${each.index}`);
          if (!position) {
            continue;
          }

          tmp_nodes.push({
            id: `${each.index}`,
            data: each,
            type: "netflow",
            label: each.name,
            draggable: false,
            selectable: false,
            connectable: each.has_target_hook() || each.has_source_hook(),
            position: {
              x: offset_x + position.x,
              y: GRAPH_TOP_MARGIN + position.y,
            },
          });
        }

        const device_indexes = new Set(new_value.map((each) => each.index));
        const tmp_edges: any[] = [];
        for (const each of new_value) {
          if (each.controller_id === undefined) {
            continue;
          }
          if (!device_indexes.has(each.controller_id)) {
            continue;
          }

          tmp_edges.push({
            id: `${each.controller_id}-${each.index}`,
            source: `${each.controller_id}`,
            target: `${each.index}`,
            label: "",
            animated: true,
            class: "normal-edge",
          });
        }

        bridges.value = new_bridges;
        eths.value = new_eths;
        nodes.value = tmp_nodes;
        edges.value = tmp_edges;

        const layout_signature = create_layout_signature(
          new_value,
          layout_width.value,
          wanLinkStore.links,
        );
        const fully_measured = new_value.every((each) =>
          node_heights.value.has(`${each.index}`),
        );
        const should_fit =
          last_layout_signature.value !== layout_signature ||
          (!heights_settled.value && fully_measured);

        if (
          node_call_back.value !== undefined &&
          view_locked.value &&
          should_fit
        ) {
          node_call_back.value();
        }

        if (fully_measured) {
          heights_settled.value = true;
        }

        last_layout_signature.value = layout_signature;
      },
      { immediate: true },
    );

    async function UPDATE_INFO() {
      const [devs] = await Promise.all([ifaces(), wanLinkStore.load()]);
      net_devs.value = devs;
    }

    /** Merge measured heights; only real changes (> 0.5px) relayout. */
    function UPDATE_NODE_HEIGHTS(incoming: Map<string, number>) {
      if (incoming.size === 0) {
        return;
      }

      const next = new Map(node_heights.value);
      let changed = false;

      for (const [key, height] of incoming) {
        const prev = next.get(key);
        if (prev === undefined || Math.abs(prev - height) > 0.5) {
          next.set(key, height);
          changed = true;
        }
      }

      if (changed) {
        node_heights.value = next;
      }
    }

    async function SETTING_CALL_BACK(call_back: () => void) {
      node_call_back.value = call_back;
    }

    function SET_LAYOUT_CONTEXT(width: number, reserved_width = 0) {
      layout_width.value = width;
      panel_reserved_width.value = reserved_width;
    }

    function FIND_BRIDGE_BY_IFINDEX(ifindex: any): boolean {
      for (const bridge of bridges.value) {
        if (bridge.ifindex == ifindex) {
          return true;
        }
      }
      return false;
    }

    function FIND_DEV_BY_IFINDEX(ifindex: any): NetDev | undefined {
      for (const dev of net_devs.value) {
        if (dev.index == ifindex) {
          return dev;
        }
      }
      return undefined;
    }

    function HIDE_DOWN(value: boolean) {
      hide_down_dev.value = value;
    }

    function TOGGLE_VIEW_LOCK() {
      view_locked.value = !view_locked.value;

      if (view_locked.value && node_call_back.value !== undefined) {
        node_call_back.value();
        last_layout_signature.value = create_layout_signature(
          visible_net_devs.value,
          layout_width.value,
          wanLinkStore.links,
        );
      }
    }

    return {
      net_devs,
      visible_net_devs,
      nodes,
      edges,
      bridges,
      eths,
      hide_down_dev,
      view_locked,
      HIDE_DOWN,
      TOGGLE_VIEW_LOCK,
      UPDATE_INFO,
      UPDATE_NODE_HEIGHTS,
      SETTING_CALL_BACK,
      SET_LAYOUT_CONTEXT,
      FIND_DEV_BY_IFINDEX,
      FIND_BRIDGE_BY_IFINDEX,
    };
  },
  {
    persist: {
      key: "iface_node_v1",
      storage: localStorage,
      pick: ["hide_down_dev", "view_locked"],
    },
  },
);
