import { ifaces } from "@/api/network";
import { DevStateType, NetDev } from "@/lib/dev";
import { ZoneType } from "@/lib/service_ipconfig";
import { defineStore } from "pinia";
import { computed, ref, watch } from "vue";

interface IfaceOption {
  label: string;
  value: string;
  ifindex: number;
}

const NODE_WIDTH = 360;
const NODE_HEIGHT = 176;
const LANE_PADDING = 48;
const GROUP_GAP = 52;
const STACK_GAP = 24;
const MIN_GRAPH_WIDTH = 940;
const MAX_GRAPH_WIDTH = 1480;

function sort_devices(devs: NetDev[]) {
  const zone_rank = (zone: ZoneType) => {
    switch (zone) {
      case ZoneType.Wan:
        return 0;
      case ZoneType.Lan:
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

function get_visible_devices(devs: NetDev[], hide_down: boolean) {
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

function create_layout_signature(devs: NetDev[], width: number) {
  return JSON.stringify({
    width,
    devices: devs.map((each) => ({
      index: each.index,
      controller_id: each.controller_id ?? null,
      zone_type: each.zone_type,
      dev_kind: each.dev_kind ?? "",
      name: each.name,
    })),
  });
}

export const useIfaceNodeStore = defineStore(
  "iface_node",
  () => {
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

    const visible_net_devs = computed(() =>
      get_visible_devices(net_devs.value, hide_down_dev.value),
    );

    watch(
      [visible_net_devs, layout_width, panel_reserved_width],
      ([new_value, current_layout_width, current_reserved_width]) => {
        const tmp_nodes: any[] = [];
        const tmp_edges: any[] = [];
        const new_bridges: IfaceOption[] = [];
        const new_eths: IfaceOption[] = [];
        const device_map = new Map(new_value.map((each) => [each.index, each]));
        const child_map = new Map<number, NetDev[]>();
        const positioned = new Set<number>();

        for (const each of new_value) {
          if (each.dev_kind === "bridge") {
            new_bridges.push({
              label: each.name,
              value: each.name,
              ifindex: each.index,
            });
          } else if (each.zone_type !== ZoneType.Wan) {
            new_eths.push({
              label: each.name,
              value: each.name,
              ifindex: each.index,
            });
          }

          if (
            each.controller_id !== undefined &&
            device_map.has(each.controller_id)
          ) {
            const children = child_map.get(each.controller_id) ?? [];
            children.push(each);
            child_map.set(each.controller_id, children);
          }
        }

        for (const [controller_id, children] of child_map) {
          child_map.set(controller_id, sort_devices(children));
        }

        const available_width = Math.max(
          layout_width.value - panel_reserved_width.value,
          MIN_GRAPH_WIDTH,
        );
        const graph_width = Math.min(available_width, MAX_GRAPH_WIDTH);
        const left_x = LANE_PADDING;
        const right_x = Math.max(
          graph_width - NODE_WIDTH - LANE_PADDING,
          left_x + NODE_WIDTH + 340,
        );
        const center_x = Math.round((left_x + right_x) / 2);

        const push_node = (each: NetDev, x: number, y: number) => {
          positioned.add(each.index);
          tmp_nodes.push({
            id: `${each.index}`,
            data: each,
            type: "netflow",
            label: each.name,
            draggable: false,
            selectable: false,
            connectable: each.has_target_hook() || each.has_source_hook(),
            position: { x, y },
          });

          if (
            each.controller_id !== undefined &&
            device_map.has(each.controller_id)
          ) {
            tmp_edges.push({
              id: `${each.controller_id}-${each.index}`,
              source: `${each.controller_id}`,
              target: `${each.index}`,
              label: "",
              animated: true,
              class: "normal-edge",
            });
          }
        };

        const is_root = (each: NetDev) =>
          each.controller_id === undefined ||
          !device_map.has(each.controller_id);

        const wan_roots = new_value.filter(
          (each) => each.zone_type === ZoneType.Wan && is_root(each),
        );
        const core_roots = new_value.filter(
          (each) => each.zone_type !== ZoneType.Wan && is_root(each),
        );

        let wan_y = 72;
        for (const each of wan_roots) {
          push_node(each, left_x, wan_y);
          wan_y += NODE_HEIGHT + STACK_GAP;
        }

        let center_y = 72;
        for (const each of core_roots) {
          const children = child_map.get(each.index) ?? [];
          const child_block_height =
            children.length > 0
              ? children.length * NODE_HEIGHT +
                (children.length - 1) * STACK_GAP
              : 0;
          const group_height = Math.max(NODE_HEIGHT, child_block_height);
          const root_y =
            center_y + Math.max((group_height - NODE_HEIGHT) / 2, 0);

          push_node(each, center_x, root_y);

          let child_y = center_y;
          for (const child of children) {
            push_node(child, right_x, child_y);
            child_y += NODE_HEIGHT + STACK_GAP;
          }

          center_y += group_height + GROUP_GAP;
        }

        let orphan_y = center_y;
        for (const each of new_value) {
          if (positioned.has(each.index)) {
            continue;
          }

          push_node(each, center_x, orphan_y);
          orphan_y += NODE_HEIGHT + STACK_GAP;
        }

        bridges.value = new_bridges;
        eths.value = new_eths;
        nodes.value = tmp_nodes;
        edges.value = tmp_edges;

        const layout_signature = create_layout_signature(
          new_value,
          current_layout_width,
        );
        const should_fit = last_layout_signature.value !== layout_signature;

        if (
          node_call_back.value !== undefined &&
          view_locked.value &&
          should_fit
        ) {
          node_call_back.value();
        }

        last_layout_signature.value = layout_signature;
      },
      { immediate: true },
    );

    async function UPDATE_INFO() {
      net_devs.value = await ifaces();
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
