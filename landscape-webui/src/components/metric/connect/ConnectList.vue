<script
  setup
  lang="ts"
  generic="T extends ConnectRealtimeStatus | ConnectHistoryStatus"
>
import { computed, ref, shallowRef, watch } from "vue";
import { useMobileLayout } from "@/composables/useMobileLayout";
import { useThemeVars, type VirtualListInst } from "naive-ui";
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronSort,
  ChevronUp,
} from "@vicons/carbon";
import type {
  ConnectHistoryStatus,
  ConnectRealtimeStatus,
  ConnectSortKey,
  SortOrder,
} from "@landscape-router/types/api/schemas";
import { useFrontEndStore } from "@/stores/front_end_config";
import ConnectListRow from "./ConnectListRow.vue";
import ConnectChartDrawer from "./ConnectChartDrawer.vue";

const props = defineProps<{
  mode: "live" | "history";
  items: T[];
  showEmpty?: boolean;
}>();
const emit = defineEmits<{ filter: [item: T] }>();
const sortKey = defineModel<ConnectSortKey>("sortKey", { required: true });
const sortOrder = defineModel<SortOrder>("sortOrder", { required: true });
const theme = useThemeVars();
const frontEnd = useFrontEndStore();
const mobile = useMobileLayout();
const cards = computed(() => mobile.value && props.mode === "live");
const mobileRows = computed(() =>
  props.items.map((item) => ({
    key: `${item.key.cpu_id}:${item.key.create_time}`,
    item,
  })),
);
const expandedKey = ref<string>();
watch(
  () =>
    expandedKey.value &&
    !mobileRows.value.some((row) => row.key === expandedKey.value),
  (missing) => {
    if (missing) expandedKey.value = undefined;
  },
);
const rowHeight = 44;
const list = ref<VirtualListInst>();
const columns = computed(
  () =>
    [
      { label: "metric.connect.col.last_report", key: "time" },
      { label: "metric.connect.filter.duration", key: "duration" },
      {
        prefix: "metric.connect.col.source",
        label: "metric.connect.filter.port_start",
        key: "port",
      },
      { label: "metric.connect.col.destination" },
      { label: "metric.connect.col.protocol_flow" },
      {
        label:
          props.mode === "live"
            ? "metric.connect.col.egress_rate"
            : "metric.connect.col.total_egress",
        key: "egress",
      },
      {
        label:
          props.mode === "live"
            ? "metric.connect.col.ingress_rate"
            : "metric.connect.col.total_ingress",
        key: "ingress",
      },
      { label: "common.actions" },
    ] as const,
);

function toggleSort(key: ConnectSortKey) {
  sortOrder.value =
    sortKey.value === key && sortOrder.value === "desc" ? "asc" : "desc";
  sortKey.value = key;
  list.value?.scrollTo({ top: 0 });
}

const showChart = ref(false);
const selected = shallowRef<T>();
const chartTitle = computed(() => {
  const item = selected.value;
  if (!item) return "";
  return `${frontEnd.MASK_INFO(item.src_ip)}:${frontEnd.MASK_PORT(item.src_port)} → ${frontEnd.MASK_INFO(item.dst_ip)}:${frontEnd.MASK_PORT(item.dst_port)}`;
});
function openChart(item: T) {
  selected.value = item;
  showChart.value = true;
}
</script>

<template>
  <div class="connection-list">
    <div
      v-if="cards"
      class="connection-cards"
      :aria-label="$t('metric.connect.switcher.connections')"
    >
      <div class="sort-controls">
        <label>
          {{ $t("metric.connect.sort_by") }}
          <select v-model="sortKey" @change="list?.scrollTo({ top: 0 })">
            <template v-for="col in columns" :key="col.label">
              <option v-if="'key' in col" :value="col.key">
                {{ $t(col.label) }}
              </option>
            </template>
          </select>
        </label>
        <n-button size="small" quaternary @click="toggleSort(sortKey)">
          <template #icon
            ><n-icon :component="sortOrder === 'asc' ? ArrowUp : ArrowDown"
          /></template>
          {{
            $t(
              sortOrder === "asc"
                ? "metric.connect.ascending"
                : "metric.connect.descending",
            )
          }}
        </n-button>
      </div>
      <n-virtual-list
        ref="list"
        class="list-body"
        :items="mobileRows"
        :item-size="110"
        item-resizable
      >
        <template #default="{ item: row, index }">
          <ConnectListRow
            :item="row.item"
            :mode="mode"
            :index="index"
            mobile
            :expanded="expandedKey === row.key"
            @toggle="
              expandedKey = expandedKey === row.key ? undefined : row.key
            "
            @filter="emit('filter', row.item)"
            @chart="openChart(row.item)"
          />
        </template>
      </n-virtual-list>
    </div>
    <div
      v-else
      class="connection-table"
      role="table"
      :aria-rowcount="items.length + 1"
      :aria-label="$t('metric.connect.switcher.connections')"
      :style="{ '--row-height': rowHeight + 'px' }"
    >
      <div class="connection-line list-header" role="row" aria-rowindex="1">
        <div
          v-for="column in columns"
          :key="column.label"
          role="columnheader"
          :aria-sort="
            'key' in column && sortKey === column.key
              ? sortOrder === 'asc'
                ? 'ascending'
                : 'descending'
              : undefined
          "
          :class="{
            numeric:
              'key' in column &&
              (column.key === 'ingress' || column.key === 'egress'),
          }"
        >
          <template v-if="'prefix' in column"
            >{{ $t(column.prefix) }} ·
          </template>
          <button
            v-if="'key' in column"
            type="button"
            @click="toggleSort(column.key)"
          >
            <n-icon
              v-if="column.key === 'egress' || column.key === 'ingress'"
              aria-hidden="true"
              :component="column.key === 'egress' ? ArrowUp : ArrowDown"
              :color="
                column.key === 'egress' ? theme.infoColor : theme.successColor
              "
            />
            {{ $t(column.label) }}
            <n-icon
              aria-hidden="true"
              :component="
                sortKey !== column.key
                  ? ChevronSort
                  : sortOrder === 'asc'
                    ? ChevronUp
                    : ChevronDown
              "
            />
          </button>
          <template v-else>{{ $t(column.label) }}</template>
        </div>
      </div>
      <n-virtual-list
        ref="list"
        class="list-body"
        :item-size="rowHeight"
        :items="items"
        :visible-items-props="{ role: 'rowgroup' }"
      >
        <template #default="{ item, index }">
          <ConnectListRow
            :item="item"
            :mode="mode"
            :index="index"
            @filter="emit('filter', item)"
            @chart="openChart(item)"
          />
        </template>
      </n-virtual-list>
    </div>
    <n-empty
      v-if="showEmpty"
      class="list-empty"
      :description="$t('metric.connect.history_state.empty')"
    />
  </div>
  <ConnectChartDrawer
    v-if="selected"
    v-model:show="showChart"
    :type="mode"
    :conn="selected.key"
    :title="chartTitle"
    :create-time-ms="selected.create_time_ms"
    :last-report-time="selected.last_report_time"
  />
</template>

<style scoped>
.connection-list {
  flex: 1;
  min-height: 0;
  min-width: 0;
  overflow-x: auto;
  position: relative;
}
.connection-cards,
.connection-table {
  --muted: v-bind("theme.textColor3");
  --upload: v-bind("theme.infoColor");
  --download: v-bind("theme.successColor");
  display: flex;
  flex-direction: column;
  height: 100%;
}
.connection-table {
  min-width: 970px;
}
.sort-controls {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-block: 2px 8px;
  font-size: 13px;
}
.sort-controls label {
  display: flex;
  align-items: center;
  gap: 8px;
  color: v-bind("theme.textColor2");
}
.sort-controls select {
  font: inherit;
  color: v-bind("theme.textColor1");
  background: v-bind("theme.cardColor");
  border: 1px solid v-bind("theme.borderColor");
  border-radius: 5px;
  padding: 5px 8px;
  max-width: 55vw;
}

.connection-table :deep(.connection-line) {
  display: grid;
  grid-template-columns:
    100px 86px minmax(132px, 1fr) minmax(132px, 1fr)
    minmax(100px, 0.45fr) 100px 100px 104px;
  align-items: center;
  gap: 10px;
  box-sizing: border-box;
  padding-inline: 12px;
}
.list-header {
  flex: none;
  height: 36px;
  background: v-bind("theme.tableHeaderColor");
  border-block: 1px solid v-bind("theme.dividerColor");
  color: v-bind("theme.textColor2");
  font-size: 12px;
  white-space: nowrap;
}
.list-header button {
  display: inline-flex;
  gap: 4px;
  align-items: center;
  padding: 4px 0;
  border: 0;
  background: transparent;
  font: inherit;
  color: inherit;
  cursor: pointer;
}
.list-header button:hover,
.list-header [aria-sort] button {
  color: v-bind("theme.primaryColor");
}
.list-header button:focus-visible {
  outline: 2px solid v-bind("theme.primaryColor");
  outline-offset: 2px;
}
.numeric {
  text-align: right;
}
.list-header > :last-child {
  text-align: center;
}
.list-body {
  flex: 1;
  min-height: 0;
}
.list-empty {
  position: absolute;
  top: 64px;
  inset-inline: 0;
}
@media (max-width: 768px) {
  .connection-table :deep(.connection-line) {
    grid-template-columns:
      minmax(152px, 1fr) minmax(152px, 1fr)
      100px 86px 100px 100px 100px 104px;
  }
  .connection-table :deep(.row-fields > :nth-child(3)),
  .connection-table :deep(.row-fields > :nth-child(4)),
  .connection-table :deep(.list-header > :nth-child(3)),
  .connection-table :deep(.list-header > :nth-child(4)) {
    order: -1;
  }
}
</style>
