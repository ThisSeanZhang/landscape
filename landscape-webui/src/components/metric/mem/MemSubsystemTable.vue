<script setup lang="ts">
import { computed, h } from "vue";
import { useI18n } from "vue-i18n";
import {
  NIcon,
  NProgress,
  NTag,
  NTooltip,
  type DataTableColumns,
} from "naive-ui";
import { HelpCircleOutline } from "@vicons/ionicons5";
import type { ModuleMemStat } from "@landscape-router/types/api/schemas";
import { formatSize, formatCount } from "@/lib/util";

const props = defineProps<{
  modules: ModuleMemStat[];
}>();

const { t } = useI18n();

const sortedModules = computed(() =>
  [...props.modules].sort((a, b) => b.live_bytes - a.live_bytes),
);

const sumLive = computed(() =>
  props.modules.reduce((sum, row) => sum + row.live_bytes, 0),
);

const columns = computed<DataTableColumns<ModuleMemStat>>(() => [
  {
    title: t("metric.mem.subsystem"),
    key: "subsystem",
    width: 130,
    render(row) {
      return h(
        NTag,
        { size: "small", bordered: false },
        { default: () => row.subsystem },
      );
    },
  },
  {
    title: t("metric.mem.live_bytes"),
    key: "live_bytes",
    width: 130,
    sorter: "default",
    render(row) {
      return h(
        "span",
        { style: { fontWeight: "600" } },
        { default: () => formatSize(row.live_bytes) },
      );
    },
  },
  {
    title() {
      return h(
        "div",
        { style: { display: "flex", alignItems: "center", gap: "4px" } },
        [
          t("metric.mem.share"),
          h(
            NTooltip,
            { trigger: "hover" },
            {
              trigger: () =>
                h(
                  NIcon,
                  { size: 14, style: { color: "#888", cursor: "help" } },
                  {
                    default: () => h(HelpCircleOutline),
                  },
                ),
              default: () => t("metric.mem.share_tip"),
            },
          ),
        ],
      );
    },
    key: "share",
    width: 180,
    render(row) {
      const percent =
        sumLive.value > 0 ? (row.live_bytes / sumLive.value) * 100 : 0;
      return h(
        "div",
        { style: { display: "flex", alignItems: "center", gap: "8px" } },
        [
          h(NProgress, {
            type: "line",
            percentage: percent,
            showIndicator: false,
            height: 8,
            style: { flex: "1", minWidth: "80px" },
          }),
          h(
            "span",
            { style: { fontSize: "12px", color: "#888" } },
            {
              default: () => `${percent.toFixed(1)}%`,
            },
          ),
        ],
      );
    },
  },
  {
    title: t("metric.mem.allocated"),
    key: "allocated_bytes",
    width: 120,
    sorter: "default",
    render: (row) => formatSize(row.allocated_bytes),
  },
  {
    title: t("metric.mem.freed"),
    key: "freed_bytes",
    width: 120,
    sorter: "default",
    render: (row) => formatSize(row.freed_bytes),
  },
  {
    title: t("metric.mem.alloc_events"),
    key: "alloc_events",
    width: 110,
    sorter: "default",
    render: (row) => formatCount(row.alloc_events),
  },
  {
    title: t("metric.mem.free_events"),
    key: "free_events",
    width: 110,
    sorter: "default",
    render: (row) => formatCount(row.free_events),
  },
]);
</script>

<template>
  <n-data-table
    :columns="columns"
    :data="sortedModules"
    :bordered="false"
    size="small"
    flex-height
    style="flex: 1; min-height: 0"
    :scroll-x="920"
    :row-key="(row: ModuleMemStat) => row.subsystem"
  />
</template>
