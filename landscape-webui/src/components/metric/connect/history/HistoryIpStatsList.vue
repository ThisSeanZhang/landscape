<script setup lang="ts">
import { h, computed } from "vue";
import { formatSize, formatCount } from "@/lib/util";
import { useThemeVars, NTooltip, NIcon, NButton } from "naive-ui";
import { Search } from "@vicons/carbon";
import type {
  IpHistoryStat,
  ConnectSortKey,
} from "landscape-types/common/metric/connect";

import FlowExhibit from "@/components/flow/FlowExhibit.vue";

import { useI18n } from "vue-i18n";
import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";
import { useMacBindingStore } from "@/stores/mac_binding";

const frontEndStore = useFrontEndStore();
const macBindingStore = useMacBindingStore();

const props = defineProps<{
  stats: IpHistoryStat[];
  title: string;
  ipLabel: string;
  sortKey: string;
  sortOrder: "asc" | "desc";
}>();

const { t } = useI18n();
const emit = defineEmits(["update:sort", "search:ip"]);

const themeVars = useThemeVars();

// 使用 computed 确保当 props.sortKey 或 props.sortOrder 改变时，列定义会更新
const columns = computed(() => [
  {
    title: props.ipLabel,
    key: "ip",
    render: (row: IpHistoryStat) => {
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
                    // 鼠标悬浮时提高不透明度
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
    render: (row: IpHistoryStat) => {
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
    title: t("metric.connect.col.total_conns"),
    key: "time",
    sorter: true,
    sortOrder:
      props.sortKey === "time"
        ? props.sortOrder === "asc"
          ? "ascend"
          : "descend"
        : false,
    render: (row: IpHistoryStat) => row.connect_count,
  },
  {
    title: t("metric.connect.col.total_egress"),
    key: "egress",
    sorter: true,
    sortOrder:
      props.sortKey === "egress"
        ? props.sortOrder === "asc"
          ? "ascend"
          : "descend"
        : false,
    render: (row: IpHistoryStat) => {
      return h(
        "span",
        {
          style: { color: themeVars.value.infoColor, fontWeight: "bold" },
        },
        formatSize(row.total_egress_bytes),
      );
    },
  },
  {
    title: t("metric.connect.col.total_ingress"),
    key: "ingress",
    sorter: true,
    sortOrder:
      props.sortKey === "ingress"
        ? props.sortOrder === "asc"
          ? "ascend"
          : "descend"
        : false,
    render: (row: IpHistoryStat) => {
      return h(
        "span",
        {
          style: { color: themeVars.value.successColor, fontWeight: "bold" },
        },
        formatSize(row.total_ingress_bytes),
      );
    },
  },
  {
    title: t("metric.connect.col.egress_pkts"),
    key: "total_egress_pkts",
    render: (row: IpHistoryStat) => formatCount(row.total_egress_pkts),
  },
  {
    title: t("metric.connect.col.ingress_pkts"),
    key: "total_ingress_pkts",
    render: (row: IpHistoryStat) => formatCount(row.total_ingress_pkts),
  },
]);

const handleSort = (sorter: any) => {
  if (sorter && sorter.order) {
    const key = sorter.columnKey as ConnectSortKey;
    const order = sorter.order === "ascend" ? "asc" : "desc";
    emit("update:sort", { key, order });
  } else {
    // 如果点击取消排序，我们默认回到按上传流量倒序
    emit("update:sort", { key: "egress", order: "desc" });
  }
};
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
      :data="stats"
      :pagination="false"
      :max-height="'calc(100vh - 350px)'"
      @update:sorter="handleSort"
    />
  </n-flex>
</template>
