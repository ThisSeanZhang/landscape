<script setup lang="ts">
import { computed, onMounted, ref, shallowRef } from "vue";
import {
  AlertCircleOutline,
  PulseOutline,
  Refresh,
  TimeOutline,
} from "@vicons/ionicons5";
import { useThemeVars } from "naive-ui";
import { useI18n } from "vue-i18n";
import type { DnsMetricConfig } from "@landscape-router/types/api/schemas";
import { get_metric_config } from "@/api/sys/config";
import { useCapabilityStore } from "@/stores/capability";
import DNSDashboard from "@/components/metric/dns/DNSDashboard.vue";
import FlowSelect from "@/components/flow/FlowSelect.vue";
import DNSHistory from "./DNSMetric.vue";

const { t } = useI18n();
const theme = useThemeVars();
const views = [
  { value: "live", icon: PulseOutline },
  { value: "history", icon: TimeOutline },
] as const;
const capability = useCapabilityStore();
const mode = ref<"live" | "history">("live");
const flowId = ref<number | null>(null);
const config = ref<DnsMetricConfig>();
const loading = ref(true);

const liveView = ref<InstanceType<typeof DNSDashboard> | null>(null);
const historyView = ref<InstanceType<typeof DNSHistory> | null>(null);
const activeView = computed(() =>
  mode.value === "live" ? liveView.value : historyView.value,
);
const refreshingView = shallowRef<typeof activeView.value>(null);
const settingsUnavailable = computed(
  () => !config.value || (mode.value === "history" && !capability.loaded),
);
const failed = computed(
  () =>
    !loading.value && (settingsUnavailable.value || !!activeView.value?.failed),
);
const refreshHint = computed(() => {
  const action = t("metric.dns.dash.refresh");
  if (!failed.value) return action;
  const reason = settingsUnavailable.value
    ? "metric.dns.settings_unavailable"
    : "metric.dns.stats_load_failed";
  return `${t(reason)} · ${action}`;
});

async function refresh() {
  const view = activeView.value;
  if (!view) return loadConfig();
  refreshingView.value = view;
  try {
    await view.refresh();
  } finally {
    if (refreshingView.value === view) refreshingView.value = null;
  }
}

async function loadConfig() {
  loading.value = true;
  try {
    const [metric] = await Promise.all([
      get_metric_config(),
      capability.LOAD(),
    ]);
    config.value = metric.dns;
  } catch {
    config.value = undefined;
  } finally {
    loading.value = false;
  }
}

onMounted(loadConfig);
</script>

<template>
  <n-flex vertical :wrap="false" class="dns-metric-page">
    <n-flex align="center" justify="space-between">
      <div
        class="view-switch"
        role="radiogroup"
        :aria-label="t('routes.dns-metric')"
      >
        <label v-for="view in views" :key="view.value">
          <input
            v-model="mode"
            type="radio"
            name="dns-view"
            :value="view.value"
          />
          <n-icon :component="view.icon" :size="16" aria-hidden="true" />
          <span>{{ t(`metric.dns.${view.value}`) }}</span>
        </label>
      </div>
      <n-flex align="center" :wrap="false" size="small">
        <FlowSelect v-model="flowId" :placeholder="t('metric.dns.all_flows')" />
        <n-button
          secondary
          :type="failed ? 'error' : 'default'"
          :loading="loading || (!!activeView && refreshingView === activeView)"
          :title="refreshHint"
          :aria-label="refreshHint"
          @click="refresh"
        >
          <template #icon
            ><n-icon
              ><component :is="failed ? AlertCircleOutline : Refresh" /></n-icon
          ></template>
          {{ t("common.refresh") }}
        </n-button>
      </n-flex>
    </n-flex>
    <n-spin v-if="loading" />
    <n-empty
      v-else-if="settingsUnavailable"
      :description="t('metric.dns.settings_unavailable')"
    />
    <n-empty
      v-else-if="config?.enabled === false"
      :description="t('metric.dns.collection_disabled')"
    />
    <DNSDashboard
      ref="liveView"
      v-else-if="mode === 'live'"
      :flow-id="flowId"
      live
    />
    <n-empty
      v-else-if="!capability.HAS('metric_persistent')"
      :description="t('metric.dns.history_unsupported')"
    />
    <n-empty
      v-else-if="config?.store.backend === 'memory'"
      :description="t('metric.dns.history_disabled')"
    >
      <template #icon><n-icon :component="TimeOutline" /></template>
      <template #extra>
        <RouterLink
          :to="{ name: 'routes.config', hash: '#dns-metric-config' }"
          custom
          v-slot="{ href, navigate }"
        >
          <n-button
            tag="a"
            :href="href"
            type="primary"
            secondary
            @click="navigate"
          >
            {{ t("metric.dns.open_storage_settings") }}
          </n-button>
        </RouterLink>
      </template>
    </n-empty>
    <DNSHistory v-else ref="historyView" v-model:flow-id="flowId" />
  </n-flex>
</template>

<style scoped>
.dns-metric-page {
  flex: 1;
  min-width: 0;
}
.view-switch {
  display: inline-flex;
  gap: 2px;
  padding: 3px;
  background: v-bind("theme.cardColor");
  border: 1px solid v-bind("theme.dividerColor");
  border-radius: 10px;
}
.view-switch label {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  min-width: 78px;
  padding: 5px 10px;
  box-sizing: border-box;
  border-radius: 6px;
  color: v-bind("theme.textColor2");
  font-weight: 500;
  line-height: 20px;
}
.view-switch input {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  margin: 0;
  opacity: 0;
  cursor: pointer;
}
.view-switch label:hover {
  background: v-bind("theme.hoverColor");
}
.view-switch label:has(:checked) {
  background: color-mix(in srgb, v-bind("theme.primaryColor") 14%, transparent);
  color: v-bind("theme.primaryColor");
}
.view-switch label:has(:focus-visible) {
  outline: 2px solid v-bind("theme.primaryColor");
}
.dns-metric-page > :deep(.n-empty) {
  box-sizing: border-box;
  min-height: 230px;
  padding: 36px 20px;
  justify-content: center;
  text-align: center;
  background: v-bind("theme.cardColor");
  border: 1px solid v-bind("theme.dividerColor");
  border-radius: 8px;
}
.dns-metric-page > :deep(.n-empty .n-empty__description) {
  max-width: 56ch;
  color: v-bind("theme.textColor2");
}
</style>
