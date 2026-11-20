<script setup lang="ts">
import { ref, shallowRef, reactive, onMounted, h, computed, watch } from "vue";
import { useI18n } from "vue-i18n";
import type { LandscapeDnsRecordType } from "@landscape-router/types/api/schemas";
import { get_dns_history } from "@/api/metric";
import {
  NDataTable,
  NTag,
  NTime,
  NButton,
  NInput,
  NDatePicker,
  NIcon,
  NTooltip,
  NTabs,
  NTab,
  NSelect,
  NInputNumber,
  NFlex,
  NEllipsis,
  useThemeVars,
} from "naive-ui";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";

const enrolledDeviceStore = useEnrolledDeviceStore();
import type { DataTableColumns } from "naive-ui";
import { parseDnsAnswer, type DnsLogEntry } from "@/lib/metric/dnsAnswer";
import DnsAnswerDrawer from "@/components/metric/dns/DnsAnswerDrawer.vue";
import {
  RefreshOutline,
  ChevronForwardOutline,
  HelpCircleOutline,
  TimeOutline,
  Search,
} from "@vicons/ionicons5";
import { useDebounceFn } from "@vueuse/core";
import DNSDashboard from "@/components/metric/dns/DNSDashboard.vue";
import FlowExhibit from "@/components/flow/FlowExhibit.vue";
import CheckDomainDrawer from "@/components/dns/CheckDomainDrawer.vue";
import { SearchLocate } from "@vicons/carbon";
import { usePreferenceStore } from "@/stores/preference";

const flowId = defineModel<number | null>("flowId", { required: true });

const prefStore = usePreferenceStore();

const activeTab = ref("history");
const dashboardRef = ref<InstanceType<typeof DNSDashboard> | null>(null);
const logFailed = ref(false);
const failed = computed(() =>
  activeTab.value === "history"
    ? logFailed.value
    : !!dashboardRef.value?.failed,
);
const showCheckDomainDrawer = ref(false);
const checkDomainName = ref("");
const checkDomainFlowId = ref(0);
const checkDomainType = ref<LandscapeDnsRecordType>("A");
const { t, n } = useI18n();
const theme = useThemeVars();

const data = ref<DnsLogEntry[]>([]);
const selectedQuery = shallowRef<DnsLogEntry>();
const showAnswers = ref(false);
const loading = ref(false);

const DEFAULT_TIME_WINDOW = 10 * 60 * 1000; // 10 minutes

const searchParams = reactive({
  domain: "",
  src_ip: "",
  query_type: null as string | null,
  status: null as string | null,
  min_duration_ms: null as number | null,
  max_duration_ms: null as number | null,
  timeRange: [Date.now() - DEFAULT_TIME_WINDOW, Date.now()] as
    [number, number] | null,
  sort_key: "time",
  sort_order: "desc" as "asc" | "desc",
});

const pagination = reactive({
  page: 1,
  pageSize: 15, // Default 15
  itemCount: 0,
  showSizePicker: true,
  pageSlot: 5,
  prefix: ({ itemCount }: { itemCount?: number }) =>
    t("metric.dns.records_found", { count: n(itemCount ?? 0) }),
  pageSizes: [15, 30, 50, 100],
  onChange: (page: number) => {
    pagination.page = page;
    loadData();
  },
  onUpdatePageSize: (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.page = 1;
    loadData();
  },
});

const formatIp = (ip: string) => {
  if (ip.startsWith("::ffff:")) {
    return ip.substring(7);
  }
  return ip;
};

const queryTypeOptions = computed(() => [
  { label: t("metric.dns.all_types"), value: undefined },
  { label: "A (IPv4)", value: "A" },
  { label: "AAAA (IPv6)", value: "AAAA" },
  { label: "CNAME", value: "CNAME" },
  { label: "MX", value: "MX" },
  { label: "TXT", value: "TXT" },
  { label: "NS", value: "NS" },
  { label: "PTR", value: "PTR" },
  { label: "SOA", value: "SOA" },
  { label: "SRV", value: "SRV" },
]);

const statusOptions = computed(() => [
  { label: t("metric.dns.all_status"), value: undefined },
  { label: t("metric.dns.status_hit"), value: "hit" },
  { label: t("metric.dns.status_normal"), value: "normal" },
  { label: t("metric.dns.status_block"), value: "block" },
  { label: t("metric.dns.status_local"), value: "local" },
  { label: t("metric.dns.status_nxdomain"), value: "nxdomain" },
  { label: t("metric.dns.status_filter"), value: "filter" },
  { label: t("metric.dns.status_error"), value: "error" },
]);

const columns = computed<DataTableColumns<DnsLogEntry>>(() => [
  {
    title: t("metric.dns.col_time"),
    key: "report_time",
    width: 200,
    sorter: true,
    sortOrder:
      searchParams.sort_key === "time"
        ? searchParams.sort_order === "asc"
          ? "ascend"
          : "descend"
        : false,
    render(row) {
      return h(NTime, {
        time: Number(row.report_time),
        type: "datetime",
        timeZone: prefStore.timezone,
      });
    },
  },
  {
    title: t("metric.dns.col_domain"),
    key: "domain",
    sorter: true,
    sortOrder:
      searchParams.sort_key === "domain"
        ? searchParams.sort_order === "asc"
          ? "ascend"
          : "descend"
        : false,
    render(row) {
      return h(
        NFlex,
        { align: "center", size: "small", wrap: false },
        {
          default: () => [
            h(
              NEllipsis,
              { tooltip: true, style: "flex: 1; min-width: 0" },
              { default: () => row.domain },
            ),
            h(
              NTooltip,
              { trigger: "hover" },
              {
                trigger: () =>
                  h(
                    NButton,
                    {
                      size: "tiny",
                      class: "domain-action",
                      "aria-label": t("metric.dns.tip.search_domain"),
                      quaternary: true,
                      circle: true,
                      onClick: (e) => {
                        e.stopPropagation();
                        searchParams.domain = row.domain;
                        loadData(true);
                      },
                    },
                    {
                      icon: () => h(NIcon, null, { default: () => h(Search) }),
                    },
                  ),
                default: () => t("metric.dns.tip.search_domain"),
              },
            ),
            h(
              NTooltip,
              { trigger: "hover" },
              {
                trigger: () =>
                  h(
                    NButton,
                    {
                      size: "tiny",
                      class: "domain-action",
                      "aria-label": t("metric.dns.tip.check_domain"),
                      quaternary: true,
                      circle: true,
                      onClick: (e) => {
                        e.stopPropagation();
                        checkDomainName.value = row.domain;
                        checkDomainFlowId.value = row.flow_id || 0;
                        checkDomainType.value = (row.query_type ||
                          "A") as LandscapeDnsRecordType;
                        showCheckDomainDrawer.value = true;
                      },
                    },
                    {
                      icon: () =>
                        h(NIcon, null, { default: () => h(SearchLocate) }),
                    },
                  ),
                default: () => t("metric.dns.tip.check_domain"),
              },
            ),
          ],
        },
      );
    },
  },
  {
    title: t("metric.dns.col_type"),
    key: "query_type",
    width: 80,
    render(row) {
      return h("span", { class: "query-type" }, row.query_type);
    },
  },
  {
    title: t("metric.dns.col_src_ip"),
    key: "src_ip",
    width: 140,
    render(row) {
      return enrolledDeviceStore.GET_NAME_WITH_FALLBACK(
        formatIp(String(row.src_ip)),
      );
    },
  },
  {
    title: t("metric.dns.col_flow"),
    key: "flow_id",
    width: 180,
    render(row) {
      if (!row.flow_id || row.flow_id === 0) {
        return h(
          "span",
          { class: "default-flow" },
          t("metric.dns.tip.default_flow"),
        );
      }
      return h(FlowExhibit, { flow_id: row.flow_id });
    },
  },
  {
    title: t("metric.dns.col_resp_code"),
    key: "response_code",
    width: 150,
    render(row) {
      const code = String(row.response_code || "").toLowerCase();
      const isOk = code === "noerror" || code === "no error";
      return h(
        "span",
        { class: isOk ? "response-ok" : "response-error" },
        row.response_code,
      );
    },
  },
  {
    title: t("metric.dns.col_status"),
    key: "status",
    width: 110,
    render(row) {
      const statusMap: Record<string, { type: any; label: string }> = {
        local: { type: "success", label: t("metric.dns.status_local") },
        block: { type: "warning", label: t("metric.dns.status_block") },
        hit: { type: "info", label: t("metric.dns.status_hit").split(" (")[0] },
        nxdomain: { type: "default", label: t("metric.dns.status_nxdomain") },
        filter: { type: "warning", label: t("metric.dns.status_filter") },
        normal: { type: "default", label: t("metric.dns.status_normal") },
        error: { type: "error", label: t("metric.dns.status_error") },
      };
      const s = statusMap[row.status] || { type: "default", label: row.status };
      return h(
        NTag,
        {
          type: s.type,
          size: "small",
          bordered: false,
          round: true,
        },
        { default: () => s.label },
      );
    },
  },
  {
    title: t("metric.dns.col_duration"),
    key: "duration_ms",
    align: "right",
    width: 120,
    sorter: true,
    sortOrder:
      searchParams.sort_key === "duration"
        ? searchParams.sort_order === "asc"
          ? "ascend"
          : "descend"
        : false,
  },
  {
    title: t("metric.dns.col_answers"),
    key: "answers",
    render(row) {
      const first = row.records[0];
      if (!first) return "—";
      const preview =
        row.records.find((r) => r.type === "A" || r.type === "AAAA") ?? first;
      const value = enrolledDeviceStore.GET_NAME_WITH_FALLBACK(
        formatIp(preview.value),
      );
      return h(
        "button",
        {
          class: "answer-preview",
          type: "button",
          "aria-haspopup": "dialog",
          "aria-label": t("metric.dns.show_answers", { domain: row.domain }),
          onClick: () => {
            selectedQuery.value = row;
            showAnswers.value = true;
          },
        },
        [
          h("span", { class: "answer-value" }, value),
          row.records.length > 1
            ? h("small", `+${row.records.length - 1}`)
            : null,
          h(NIcon, {
            component: ChevronForwardOutline,
            size: 13,
            "aria-hidden": true,
          }),
        ],
      );
    },
  },
]);

let requestId = 0;
const loadData = async (resetPage = false) => {
  if (resetPage) pagination.page = 1;
  if (activeTab.value === "dashboard") {
    return dashboardRef.value?.refresh();
  }

  const id = ++requestId;
  loading.value = true;
  try {
    const params: any = {
      limit: pagination.pageSize,
      offset: (pagination.page - 1) * pagination.pageSize,
      sort_key: searchParams.sort_key,
      sort_order: searchParams.sort_order,
    };

    if (searchParams.domain && searchParams.domain.trim()) {
      params.domain = searchParams.domain.trim();
    }
    if (searchParams.src_ip && searchParams.src_ip.trim()) {
      params.src_ip = searchParams.src_ip.trim();
    }
    if (searchParams.query_type) {
      params.query_type = searchParams.query_type;
    }
    if (searchParams.status) {
      params.status = searchParams.status;
    }
    if (
      searchParams.min_duration_ms !== null &&
      searchParams.min_duration_ms !== undefined
    ) {
      params.min_duration_ms = searchParams.min_duration_ms;
    }
    if (
      searchParams.max_duration_ms !== null &&
      searchParams.max_duration_ms !== undefined
    ) {
      params.max_duration_ms = searchParams.max_duration_ms;
    }
    if (flowId.value !== null) {
      params.flow_id = flowId.value;
    }

    const now = Date.now();
    params.start_time =
      searchParams.timeRange?.[0] || now - DEFAULT_TIME_WINDOW;
    params.end_time = searchParams.timeRange?.[1] || now;

    const res = await get_dns_history(params, { silent: true });
    if (id !== requestId) return;
    data.value = res.items.map((row, index) => ({
      ...row,
      rowIndex: params.offset + index,
      records: (row.answers ?? []).map(parseDnsAnswer),
    }));
    pagination.itemCount = res.total;
    logFailed.value = false;
  } catch (e) {
    if (id === requestId) logFailed.value = true;
    console.error(e);
  } finally {
    if (id === requestId) loading.value = false;
  }
};

const debouncedLoadData = useDebounceFn(() => {
  loadData(true);
}, 500);

watch(
  () => [
    searchParams.domain,
    searchParams.src_ip,
    searchParams.query_type,
    searchParams.status,
    searchParams.min_duration_ms,
    searchParams.max_duration_ms,
  ],
  () => debouncedLoadData(),
);

watch(
  () => [searchParams.timeRange, flowId.value],
  () => {
    // 仅在历史记录模式下触发 loadData
    // 仪表盘模式下，DNSDashboard 组件内部会自行执行其 timeRange 的监听逻辑
    if (activeTab.value === "history") {
      loadData(true);
    }
  },
);

const handleSorterChange = (sorter: any) => {
  if (!sorter || !sorter.order) {
    searchParams.sort_key = "time";
    searchParams.sort_order = "desc";
  } else {
    const keyMap: Record<string, string> = {
      report_time: "time",
      domain: "domain",
      duration_ms: "duration",
    };
    searchParams.sort_key = keyMap[sorter.columnKey] || "time";
    searchParams.sort_order = sorter.order === "ascend" ? "asc" : "desc";
  }
  loadData(true);
};

const shortcuts = {
  "20m": () => [Date.now() - 20 * 60 * 1000, Date.now()] as [number, number],
  "1h": () => [Date.now() - 60 * 60 * 1000, Date.now()] as [number, number],
  "12h": () =>
    [Date.now() - 12 * 60 * 60 * 1000, Date.now()] as [number, number],
  "24h": () =>
    [Date.now() - 24 * 60 * 60 * 1000, Date.now()] as [number, number],
};

const syncToNow = () => {
  if (searchParams.timeRange && searchParams.timeRange.length === 2) {
    const duration = searchParams.timeRange[1] - searchParams.timeRange[0];
    const now = Date.now();
    searchParams.timeRange = [now - duration, now];
  } else {
    searchParams.timeRange = [Date.now() - DEFAULT_TIME_WINDOW, Date.now()];
  }
  // 不再手动调用 loadData(true)
  // 1. 对于历史模式，上面的 searchParams.timeRange 变化会触发 watch
  // 2. 对于仪表盘模式，子组件的 props.timeRange 变化会触发其内部加载
};

watch(
  () => activeTab.value,
  (tab) => {
    if (tab === "dashboard") {
      dashboardRef.value?.refresh();
    } else {
      loadData(true);
    }
  },
);

const handleReset = () => {
  searchParams.domain = "";
  searchParams.src_ip = "";
  searchParams.query_type = null;
  searchParams.status = null;
  searchParams.min_duration_ms = null;
  searchParams.max_duration_ms = null;
  flowId.value = null;
  searchParams.timeRange = [Date.now() - DEFAULT_TIME_WINDOW, Date.now()];
  searchParams.sort_key = "time";
  searchParams.sort_order = "desc";
  loadData(true);
};
onMounted(() => loadData());
defineExpose({ refresh: () => loadData(), failed });
</script>

<template>
  <div class="dns-history">
    <div class="history-controls">
      <div class="history-toolbar">
        <n-tabs
          class="history-tabs"
          v-model:value="activeTab"
          type="bar"
          size="small"
        >
          <n-tab name="history">{{ t("metric.dns.query_log") }}</n-tab>
          <n-tab name="dashboard">{{ t("metric.dns.range_stats") }}</n-tab>
        </n-tabs>
        <div class="history-time">
          <n-date-picker
            v-model:value="searchParams.timeRange"
            class="history-dates"
            size="small"
            type="datetimerange"
            clearable
            :shortcuts="shortcuts"
            :placeholder="t('metric.dns.time_range')"
            :time-picker-props="{ timeZone: prefStore.timezone }"
          />
          <n-tooltip>
            <template #trigger>
              <n-button size="small" secondary @click="syncToNow">
                <template #icon
                  ><n-icon><TimeOutline /></n-icon
                ></template>
                {{ t("metric.dns.now") }}
              </n-button>
            </template>
            {{ t("metric.dns.sync_to_now_tip") }}
          </n-tooltip>
          <n-button size="small" quaternary @click="handleReset">
            <template #icon
              ><n-icon><RefreshOutline /></n-icon
            ></template>
            {{ t("metric.dns.reset") }}
          </n-button>
        </div>
      </div>
      <div v-if="activeTab === 'history'" class="history-filters">
        <div>
          <div class="domain-label">
            <label for="dns-domain">{{ t("metric.dns.domain") }}</label>
            <n-tooltip
              ><template #trigger
                ><n-icon
                  :component="HelpCircleOutline"
                  tabindex="0"
                  :aria-label="t('metric.dns.auto_search_tip')" /></template
              >{{ t("metric.dns.auto_search_tip") }}</n-tooltip
            >
          </div>
          <n-input
            v-model:value="searchParams.domain"
            :input-props="{ id: 'dns-domain' }"
            size="small"
            placeholder="example.com"
            clearable
          >
            <template #prefix><n-icon :component="Search" /></template>
          </n-input>
        </div>
        <div>
          <label for="dns-source-ip">{{ t("metric.dns.col_src_ip") }}</label>
          <n-input
            v-model:value="searchParams.src_ip"
            :input-props="{ id: 'dns-source-ip' }"
            size="small"
            placeholder="192.0.2.1"
            clearable
          />
        </div>
        <div>
          <label for="dns-query-type">{{ t("metric.dns.type") }}</label>
          <n-select
            v-model:value="searchParams.query_type"
            :input-props="{ id: 'dns-query-type' }"
            size="small"
            :options="queryTypeOptions"
            :placeholder="t('metric.dns.all_types')"
            clearable
          />
        </div>
        <div>
          <label for="dns-query-status">{{ t("metric.dns.status") }}</label>
          <n-select
            v-model:value="searchParams.status"
            :input-props="{ id: 'dns-query-status' }"
            size="small"
            :options="statusOptions"
            :placeholder="t('metric.dns.all_status')"
            clearable
          />
        </div>
        <div>
          <span class="filter-label">{{ t("metric.dns.col_duration") }}</span>
          <div class="duration-filter">
            <n-input-number
              v-model:value="searchParams.min_duration_ms"
              :input-props="{ 'aria-label': t('metric.dns.min_ms') }"
              size="small"
              :placeholder="t('metric.dns.min_ms')"
              clearable
              :min="0"
              :show-button="false"
            />
            <span aria-hidden="true">–</span>
            <n-input-number
              v-model:value="searchParams.max_duration_ms"
              :input-props="{ 'aria-label': t('metric.dns.max_ms') }"
              size="small"
              :placeholder="t('metric.dns.max_ms')"
              clearable
              :min="0"
              :show-button="false"
            />
          </div>
        </div>
      </div>
    </div>
    <n-data-table
      v-if="activeTab === 'history'"
      table-layout="fixed"
      :scroll-x="1280"
      remote
      :columns="columns"
      :data="data"
      :loading="loading"
      :pagination="pagination"
      @update:sorter="handleSorterChange"
      size="small"
      :row-key="(row) => row.rowIndex"
      :bordered="false"
      :theme-overrides="{
        tdColorSorting: theme.cardColor,
        thPaddingSmall: '9px 12px',
        tdPaddingSmall: '7px 12px',
        paginationMargin: '0',
      }"
      class="dns-history-table"
    />
    <DNSDashboard
      v-else
      ref="dashboardRef"
      :time-range="searchParams.timeRange"
      :flow-id="flowId"
    />
    <DnsAnswerDrawer
      v-if="selectedQuery"
      v-model:show="showAnswers"
      :query="selectedQuery"
    />
    <CheckDomainDrawer
      v-model:show="showCheckDomainDrawer"
      :initial-domain="checkDomainName"
      :flow_id="checkDomainFlowId"
      :initial-type="checkDomainType"
    />
  </div>
</template>

<style scoped>
.dns-history {
  container-type: inline-size;
  min-width: 0;
  display: grid;
  gap: 12px;
}
.history-controls,
.dns-history-table {
  box-sizing: border-box;
  background: v-bind("theme.cardColor");
  border: 1px solid v-bind("theme.dividerColor");
  border-radius: 8px;
  min-width: 0;
}
.history-toolbar,
.history-time,
.domain-label,
.duration-filter {
  display: flex;
  align-items: center;
  gap: 8px;
}
.history-toolbar {
  justify-content: space-between;
  flex-wrap: wrap;
  padding: 12px 16px;
  gap: 12px;
}
.history-tabs {
  width: max-content;
  max-width: 100%;
}
.history-time {
  flex-wrap: wrap;
  max-width: 100%;
}
.history-dates {
  width: 390px;
  max-width: 100%;
}
.history-filters {
  display: grid;
  grid-template-columns: 2fr 1.4fr 1fr 1fr 1.65fr;
  gap: 10px 16px;
  padding: 12px 16px 16px;
  border-top: 1px solid v-bind("theme.dividerColor");
}
.history-filters > div,
.duration-filter > * {
  min-width: 0;
}
.history-filters label,
.filter-label,
.domain-label,
.duration-filter > span {
  color: v-bind("theme.textColor3");
  font-size: 12px;
}
.history-filters label,
.filter-label {
  display: block;
  margin-bottom: 4px;
}
.domain-label {
  gap: 5px;
  margin-bottom: 4px;
}
.domain-label label {
  margin: 0;
}
.dns-history-table {
  overflow: hidden;
  font-variant-numeric: tabular-nums;
}
.dns-history-table :deep(.n-data-table__pagination) {
  padding: 10px 14px;
}
.dns-history-table :deep(.n-pagination) {
  width: 100%;
  justify-content: flex-end;
  flex-wrap: wrap;
  row-gap: 6px;
}
.dns-history-table :deep(.n-pagination-prefix) {
  margin-right: auto;
  color: v-bind("theme.textColor3");
  font-size: 12px;
}
.dns-history-table :deep(.default-flow) {
  color: v-bind("theme.textColor3");
}
.dns-history-table :deep(.answer-preview) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  max-width: 100%;
  padding: 2px 0;
  border: 0;
  background: transparent;
  color: v-bind("theme.textColor2");
  font: inherit;
  cursor: pointer;
}
.dns-history-table :deep(.answer-value) {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.dns-history-table :deep(.answer-preview small) {
  color: v-bind("theme.textColor3");
}
.dns-history-table :deep(.answer-preview:hover),
.dns-history-table :deep(.answer-preview:focus-visible) {
  color: v-bind("theme.primaryColor");
}
.dns-history-table :deep(.query-type),
.dns-history-table :deep(.response-ok),
.dns-history-table :deep(.response-error) {
  font-size: 12px;
  font-weight: 500;
}
.dns-history-table :deep(.response-ok) {
  color: v-bind("theme.successColor");
}
.dns-history-table :deep(.response-error) {
  color: v-bind("theme.errorColor");
}
@media (hover: hover) {
  .dns-history-table :deep(tr:not(:hover):not(:focus-within) .domain-action) {
    opacity: 0;
  }
}
@container (max-width: 900px) {
  .history-filters {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .history-filters > :last-child {
    grid-column: span 2;
  }
}
@container (max-width: 600px) {
  .history-filters {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .history-time {
    width: 100%;
  }
  .history-dates {
    flex-basis: 100%;
  }
}
</style>
