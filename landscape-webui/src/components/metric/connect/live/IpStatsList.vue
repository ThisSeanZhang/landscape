<script setup lang="ts">
import { ref, computed, h } from "vue";
import { formatRate, formatPackets } from "@/lib/util";
import { useThemeVars, NTooltip, NIcon, NButton } from "naive-ui";
import { Search } from "@vicons/carbon";
import type { IpRealtimeStat } from "landscape-types/common/metric/connect";
import FlowExhibit from "@/components/flow/FlowExhibit.vue";

import { useI18n } from "vue-i18n";
import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";
import { useMacBindingStore } from "@/stores/mac_binding";

const frontEndStore = useFrontEndStore();
const macBindingStore = useMacBindingStore();

const props = defineProps<{
  stats: any[]; // 更通用的类型，支持带 flow_id
  title: string;
  ipLabel: string;
}>();

const { t } = useI18n();
const emit = defineEmits(["search:ip"]);

const themeVars = useThemeVars();

const sortKey = ref<string>("egress_bps");
const sortOrder = ref<"asc" | "desc">("desc");

const columns = computed(() => [
  {
    title: props.ipLabel,
    key: "ip",
    sorter: "default",
    render: (row: any) => {
      return h(
        "div",
        { style: { display: "flex", alignItems: "center", gap: "12px" } },
        [
          h("div", { style: { display: "flex", flexDirection: "column" } }, [
            h(
              "span",
              { style: { fontWeight: "500" } },
              macBindingStore.GET_NAME_WITH_FALLBACK(row.ip),
            ),
            macBindingStore.GET_NAME_WITH_FALLBACK(row.ip) !==
            frontEndStore.MASK_INFO(row.ip)
              ? h(
                  "span",
                  { style: { fontSize: "12px", opacity: 0.5 } },
                  frontEndStore.MASK_INFO(row.ip),
                )
              : null,
          ]),
          h(
            NTooltip,
            { trigger: "hover", placement: "right" },
            {
              trigger: () =>
                h(
                  NButton,
                  {
                    text: true,
                    style: {
                      fontSize: "16px",
                      color: themeVars.value.infoColor,
                      opacity: 0.6,
                      display: "flex",
                      transition: "opacity 0.2s",
                    },
                    onMouseenter: (e: MouseEvent) => {
                      (e.currentTarget as HTMLElement).style.opacity = "1";
                    },
                    onMouseleave: (e: MouseEvent) => {
                      (e.currentTarget as HTMLElement).style.opacity = "0.6";
                    },
                    onClick: () => emit("search:ip", row.ip),
                  },
                  {
                    icon: () => h(NIcon, { component: Search }),
                  },
                ),
              default: () => t("metric.connect.tip.search_ip"),
            },
          ),
        ],
      );
    },
  },
  {
    title: t("metric.connect.col.flow"),
    key: "flow_id",
    render: (row: any) => {
      if (row.flow_id === undefined) return "-";
      if (row.flow_id === 0) {
        return h(
          "n-tag",
          {
            type: "info",
            bordered: false,
            size: "small",
            style: { opacity: 0.6 },
          },
          { default: () => t("metric.connect.tip.default_flow") },
        );
      }
      return h(FlowExhibit, {
        flow_id: row.flow_id,
      });
    },
  },
  {
    title: t("metric.connect.col.active_conns"),
    key: "active_conns",
    sorter: (a: any, b: any) => a.stats.active_conns - b.stats.active_conns,
    render: (row: any) => row.stats.active_conns,
  },
  {
    title: t("metric.connect.col.egress_rate"),
    key: "egress_bps",
    sorter: (a: any, b: any) => a.stats.egress_bps - b.stats.egress_bps,
    render: (row: any) => {
      return h(
        "span",
        {
          style: { color: themeVars.value.infoColor, fontWeight: "bold" },
        },
        formatRate(row.stats.egress_bps),
      );
    },
  },
  {
    title: t("metric.connect.col.ingress_rate"),
    key: "ingress_bps",
    sorter: (a: any, b: any) => a.stats.ingress_bps - b.stats.ingress_bps,
    render: (row: any) => {
      return h(
        "span",
        {
          style: { color: themeVars.value.successColor, fontWeight: "bold" },
        },
        formatRate(row.stats.ingress_bps),
      );
    },
  },
  {
    title: t("metric.connect.col.egress_pps"),
    key: "egress_pps",
    sorter: (a: any, b: any) => a.stats.egress_pps - b.stats.egress_pps,
    render: (row: any) => formatPackets(row.stats.egress_pps),
  },
  {
    title: t("metric.connect.col.ingress_pps"),
    key: "ingress_pps",
    sorter: (a: any, b: any) => a.stats.ingress_pps - b.stats.ingress_pps,
    render: (row: any) => formatPackets(row.stats.ingress_pps),
  },
]);

const handleSort = (sorter: any) => {
  if (sorter) {
    sortKey.value = sorter.columnKey;
    sortOrder.value = sorter.order === "ascend" ? "asc" : "desc";
  }
};

const processedData = computed(() => {
  const data = [...props.stats];
  return data.sort((a: any, b: any) => {
    let vA, vB;
    if (sortKey.value === "ip") {
      vA = a.ip;
      vB = b.ip;
    } else {
      vA = a.stats[sortKey.value];
      vB = b.stats[sortKey.value];
    }
    const result = vA > vB ? 1 : vA < vB ? -1 : 0;
    return sortOrder.value === "asc" ? result : -result;
  });
});
</script>

<template>
  <n-flex vertical style="flex: 1; overflow: hidden">
    <n-flex align="center" justify="space-between" style="margin-bottom: 12px">
      <n-h3 style="margin: 0">{{ title }}</n-h3>
      <n-text depth="3">
        {{ $t("metric.connect.stats.total_nodes", { count: stats.length }) }}
      </n-text>
    </n-flex>

    <n-data-table
      remote
      size="small"
      :columns="columns"
      :data="processedData"
      :pagination="false"
      :max-height="'calc(100vh - 350px)'"
      @update:sorter="handleSort"
    />
  </n-flex>
</template>
