<script setup lang="ts">
import { ref, reactive, onMounted, h, computed, watch } from "vue";
import { useI18n } from "vue-i18n";
import { DnsMetric, get_dns_history } from "@/api/metric";
import {
  NDataTable,
  NTag,
  NTime,
  NButton,
  NSpace,
  NInput,
  NDatePicker,
  NIcon,
  NTooltip,
  NTabs,
  NTabPane,
  NSelect,
  NInputNumber,
  NFlex,
  NEllipsis,
} from "naive-ui";
import { useMacBindingStore } from "@/stores/mac_binding";

const macBindingStore = useMacBindingStore();
import { useFrontEndStore } from "@/stores/front_end_config";
import type { DataTableColumns } from "naive-ui";
import {
  Refresh,
  TrashOutline,
  HelpCircleOutline,
  TimeOutline,
  Search,
} from "@vicons/ionicons5";
import { useDebounceFn } from "@vueuse/core";
import DNSDashboard from "./DNSDashboard.vue";
import FlowExhibit from "@/components/flow/FlowExhibit.vue";
import CheckDomainDrawer from "@/components/dns/CheckDomainDrawer.vue";
import { SearchLocate } from "@vicons/carbon";
import { usePreferenceStore } from "@/stores/preference";
import { get_flow_rules } from "@/api/flow";
import { FlowConfig } from "landscape-types/common/flow";
const prefStore = usePreferenceStore();

const activeTab = ref("dashboard");
const dashboardRef = ref<any>(null);
const showCheckDomainDrawer = ref(false);
const checkDomainName = ref("");
const checkDomainFlowId = ref(0);
const checkDomainType = ref("A");
const { t } = useI18n();
const frontEndStore = useFrontEndStore();

const data = ref<DnsMetric[]>([]);
const loading = ref(false);

const DEFAULT_TIME_WINDOW = 20 * 60 * 1000; // 20 minutes

const searchParams = reactive({
  domain: "",
  src_ip: "",
  query_type: null as string | null,
  status: null as string | null,
  min_duration_ms: null as number | null,
  max_duration_ms: null as number | null,
  flow_id: null as number | null,
  timeRange: [Date.now() - DEFAULT_TIME_WINDOW, Date.now()] as
    | [number, number]
    | null,
  sort_key: "time",
  sort_order: "desc" as "asc" | "desc",
});

const pagination = reactive({
  page: 1,
  pageSize: 15, // Default 15
  itemCount: 0,
  showSizePicker: true,
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

const flows = ref<FlowConfig[]>([]);
const flowOptions = computed(() => {
  const opts = flows.value.map((f) => ({
    label: f.remark ? `${f.flow_id} - ${f.remark}` : `Flow ${f.flow_id}`,
    value: f.flow_id,
  }));
  return [
    { label: t("metric.dns.all_flows") || "All Flows", value: null as any },
    ...opts,
  ];
});

const loadFlows = async () => {
  flows.value = await get_flow_rules();
};

const columns = computed<DataTableColumns<DnsMetric>>(() => [
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
                      quaternary: true,
                      circle: true,
                      onClick: (e) => {
                        e.stopPropagation();
                        checkDomainName.value = row.domain;
                        checkDomainFlowId.value = row.flow_id || 0;
                        checkDomainType.value = row.query_type || "A";
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
      return h(
        NTag,
        { type: "info", size: "small" },
        { default: () => row.query_type },
      );
    },
  },
  {
    title: t("metric.dns.col_src_ip"),
    key: "src_ip",
    width: 140,
    render(row) {
      return macBindingStore.GET_NAME_WITH_FALLBACK(
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
          NTag,
          {
            type: "info",
            bordered: false,
            size: "small",
            style: { opacity: 0.6 },
          },
          { default: () => t("metric.dns.tip.default_flow") },
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
        NTag,
        {
          type: isOk ? "success" : "error",
          size: "small",
          style: { minWidth: "80px", justifyContent: "center" },
        },
        { default: () => row.response_code },
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
          style: { minWidth: "70px", justifyContent: "center" },
        },
        { default: () => s.label },
      );
    },
  },
  {
    title: t("metric.dns.col_duration"),
    key: "duration_ms",
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
    ellipsis: {
      tooltip: true,
    },
    render(row) {
      if (!row.answers || row.answers.length === 0) return "-";
      return row.answers
        .map((ip) => macBindingStore.GET_NAME_WITH_FALLBACK(formatIp(ip)))
        .join(", ");
    },
  },
]);

const loadData = async (resetPage = false) => {
  if (resetPage) pagination.page = 1;
  if (activeTab.value === "dashboard") {
    dashboardRef.value?.refresh();
    return;
  }

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
    if (searchParams.flow_id !== null && searchParams.flow_id !== undefined) {
      params.flow_id = searchParams.flow_id;
    }

    const now = Date.now();
    params.start_time =
      searchParams.timeRange?.[0] || now - DEFAULT_TIME_WINDOW;
    params.end_time = searchParams.timeRange?.[1] || now;

    const res = await get_dns_history(params);
    data.value = res.items;
    pagination.itemCount = res.total;
  } catch (e) {
    console.error(e);
  } finally {
    loading.value = false;
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
  () => searchParams.timeRange,
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
  searchParams.flow_id = null;
  searchParams.timeRange = [Date.now() - DEFAULT_TIME_WINDOW, Date.now()];
  searchParams.sort_key = "time";
  searchParams.sort_order = "desc";
  loadData(true);
};

onMounted(() => {
  loadFlows();
  // 初始加载时，如果是仪表盘模式，由于它是首个展示的 Tab 且 Prop 已初始化，
  // DNSDashboard 的 immediate watch 会负责首次加载。
  // 我们只在初始是历史记录页面时才手动加载。
  if (activeTab.value === "history") {
    loadData();
  }
});
</script>

<template>
  <div style="width: 100%; padding: 12px">
    <div
      style="
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 10px;
      "
    >
      <h3 style="margin: 0; font-weight: 500; font-size: 1.1rem">
        {{ t("metric.dns.title") }}
      </h3>
      <n-space :size="8">
        <n-tooltip trigger="hover">
          <template #trigger>
            <n-icon
              size="18"
              style="
                vertical-align: middle;
                cursor: help;
                color: rgba(0, 0, 0, 0.35);
              "
            >
              <HelpCircleOutline />
            </n-icon>
          </template>
          {{ t("metric.dns.auto_search_tip") }}
        </n-tooltip>
        <n-button circle size="tiny" @click="loadData(true)" tertiary>
          <template #icon>
            <n-icon><Refresh /></n-icon>
          </template>
        </n-button>
      </n-space>
    </div>

    <div v-if="activeTab === 'dashboard'" style="margin-bottom: 10px">
      <n-space align="center" :size="[8, 8]" :wrap="false">
        <n-select
          v-model:value="searchParams.flow_id"
          size="small"
          :options="flowOptions"
          :placeholder="t('metric.dns.all_flows')"
          clearable
          style="width: 160px"
        />
        <n-date-picker
          v-model:value="searchParams.timeRange"
          size="small"
          type="datetimerange"
          clearable
          :shortcuts="shortcuts"
          :placeholder="t('metric.dns.time_range')"
          style="width: 320px"
          :time-picker-props="{ timeZone: prefStore.timezone }"
        />
        <n-tooltip trigger="hover">
          <template #trigger>
            <n-button
              strong
              secondary
              size="small"
              @click="syncToNow"
              type="info"
            >
              <template #icon>
                <n-icon><TimeOutline /></n-icon>
              </template>
              {{ t("metric.dns.now") }}
            </n-button>
          </template>
          {{ t("metric.dns.sync_to_now_tip") }}
        </n-tooltip>
        <n-button @click="handleReset" size="small" secondary>
          <template #icon
            ><n-icon><TrashOutline /></n-icon
          ></template>
          {{ t("metric.dns.reset") }}
        </n-button>
      </n-space>
    </div>

    <div v-if="activeTab === 'history'" style="margin-bottom: 10px">
      <n-space align="center" :size="[8, 8]" :wrap="false">
        <n-input
          v-model:value="searchParams.domain"
          size="small"
          :placeholder="t('metric.dns.domain')"
          clearable
          style="width: 200px"
        />
        <n-select
          v-model:value="searchParams.flow_id"
          size="small"
          :options="flowOptions"
          :placeholder="t('metric.dns.all_flows')"
          clearable
          style="width: 120px"
        />
        <n-input
          v-model:value="searchParams.src_ip"
          size="small"
          :placeholder="t('metric.dns.ip')"
          clearable
          style="width: 140px"
        />
        <n-select
          v-model:value="searchParams.query_type"
          size="small"
          :options="queryTypeOptions"
          :placeholder="t('metric.dns.type')"
          clearable
          style="width: 130px"
        />
        <n-select
          v-model:value="searchParams.status"
          size="small"
          :options="statusOptions"
          :placeholder="t('metric.dns.status')"
          clearable
          style="width: 130px"
        />
        <n-input-number
          v-model:value="searchParams.min_duration_ms"
          size="small"
          :placeholder="t('metric.dns.min_ms')"
          clearable
          :min="0"
          :show-button="false"
          style="width: 80px"
        />
        <n-input-number
          v-model:value="searchParams.max_duration_ms"
          size="small"
          :placeholder="t('metric.dns.max_ms')"
          clearable
          :min="0"
          :show-button="false"
          style="width: 80px"
        />
        <n-date-picker
          v-model:value="searchParams.timeRange"
          size="small"
          type="datetimerange"
          clearable
          :shortcuts="shortcuts"
          :placeholder="t('metric.dns.time_range')"
          style="width: 320px"
          :time-picker-props="{ timeZone: prefStore.timezone }"
        />
        <n-tooltip trigger="hover">
          <template #trigger>
            <n-button
              strong
              secondary
              size="small"
              @click="syncToNow"
              type="info"
            >
              <template #icon>
                <n-icon><TimeOutline /></n-icon>
              </template>
              {{ t("metric.dns.now") }}
            </n-button>
          </template>
          {{ t("metric.dns.sync_to_now_tip") }}
        </n-tooltip>
        <n-button @click="handleReset" size="small" secondary>
          <template #icon
            ><n-icon><TrashOutline /></n-icon
          ></template>
          {{ t("metric.dns.reset") }}
        </n-button>
      </n-space>
    </div>

    <n-tabs v-model:value="activeTab" type="line" animated>
      <n-tab-pane name="dashboard" :tab="t('metric.dns.dashboard')">
        <DNSDashboard
          ref="dashboardRef"
          :time-range="searchParams.timeRange"
          :flow-id="searchParams.flow_id"
        />
      </n-tab-pane>
      <n-tab-pane name="history" :tab="t('metric.dns.query_log')">
        <n-data-table
          remote
          :columns="columns"
          :data="data"
          :loading="loading"
          :pagination="pagination"
          @update:sorter="handleSorterChange"
          size="small"
          :row-key="(row) => row.report_time + row.domain + row.flow_id"
          :bordered="false"
          class="dns-history-table"
        />
      </n-tab-pane>
    </n-tabs>

    <CheckDomainDrawer
      v-model:show="showCheckDomainDrawer"
      :initial-domain="checkDomainName"
      :flow_id="checkDomainFlowId"
      :initial-type="checkDomainType"
    />
  </div>
</template>

<style scoped>
.dns-history-table :deep(.n-data-table-wrapper) {
  border-radius: 8px;
}
</style>
