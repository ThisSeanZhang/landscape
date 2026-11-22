<script setup lang="ts">
import type {
  DNSRuleConfig,
  CheckChainDnsResult,
  CheckDomainParams,
  DNSRedirectRule,
  LandscapeDnsRecordType,
} from "@landscape-router/types/api/schemas";
import { computed, ref } from "vue";
import { useMessage, useThemeVars } from "naive-ui";
import { useI18n } from "vue-i18n";
import { SearchLocate } from "@vicons/carbon";

import {
  check_domain,
  invalidate_domain_cache,
  refresh_domain_cache,
} from "@/api/dns_service";
import DnsQueryRecords from "./DnsQueryRecords.vue";
import { createDnsRule } from "@/lib/dns";
import { getDnsRule } from "@landscape-router/types/api/dns-rules/dns-rules";
import { get_dns_redirect } from "@/api/dns_rule/redirect";
const message = useMessage();
const theme = useThemeVars();
const { t } = useI18n();

interface Props {
  flow_id?: number;
  initialDomain?: string;
  initialType?: LandscapeDnsRecordType;
}

const props = withDefaults(defineProps<Props>(), {
  flow_id: 0,
  initialDomain: "",
  initialType: "A",
});
const emit = defineEmits<{ rulesChanged: [] }>();

const show = defineModel<boolean>("show", { required: true });
const req = ref<CheckDomainParams>({
  flow_id: 0,
  domain: "",
  record_type: "A",
});
const result = ref<CheckChainDnsResult>();
let lastRequest: CheckDomainParams | undefined;
const isUpstreamResult = computed(() =>
  Boolean(
    result.value?.rule_id &&
    !result.value.redirect_id &&
    !result.value.dynamic_redirect_source,
  ),
);
const answerTitle = computed(() => {
  if (result.value?.redirect_id || result.value?.dynamic_redirect_source) {
    return t("dns.check_domain.redirect_result");
  }
  return isUpstreamResult.value
    ? t("dns.check_domain.upstream_result")
    : t("dns.check_domain.query_result");
});

async function init_req(isEnter = false) {
  req.value = {
    flow_id: props.flow_id,
    domain: props.initialDomain || "",
    record_type: props.initialType || "A",
  };
  result.value = undefined;
  lastRequest = undefined;
  config_rule.value = undefined;
  redirect_rule.value = undefined;
  if (isEnter && req.value.domain) {
    await query();
  }
}
const options = [
  {
    label: "A",
    value: "A",
  },
  {
    label: "AAAA",
    value: "AAAA",
  },
  {
    label: "HTTPS",
    value: "HTTPS",
  },
];

const quickQueryButtonTypes = {
  A: "info",
  AAAA: "success",
  HTTPS: "warning",
} as const;

const quickQueries = computed(
  () =>
    [
      {
        name: t("dns.check_domain.baidu"),
        queries: [
          { label: "IPv4", type: "A", domain: "www.baidu.com" },
          { label: "IPv6", type: "AAAA", domain: "www.baidu.com" },
        ],
      },
      {
        name: "Cloudflare",
        queries: [
          { label: "HTTPS", type: "HTTPS", domain: "crypto.cloudflare.com" },
        ],
      },
      {
        name: t("dns.check_domain.ustc"),
        queries: [
          { label: "IPv4", type: "A", domain: "test.ustc.edu.cn" },
          { label: "IPv6", type: "AAAA", domain: "test6.ustc.edu.cn" },
        ],
      },
    ] as const,
);

function extractDomain(input: string): string {
  let s = input.trim();
  try {
    return new URL(s).hostname;
  } catch {
    s = s.replace(/\/.*$/, "");
  }
  // Convert IDN (e.g. Chinese domains) to Punycode
  try {
    return new URL("http://" + s).hostname;
  } catch {
    return s;
  }
}

const loading = ref(false);
const deleteCacheLoading = ref(false);
const refreshCacheLoading = ref(false);
const config_rule = ref<DNSRuleConfig>();
const redirect_rule = ref<DNSRedirectRule>();
const busy = computed(
  () => loading.value || deleteCacheLoading.value || refreshCacheLoading.value,
);

function onRuleChanged() {
  emit("rulesChanged");
  return refreshMatch();
}

function refreshMatch() {
  if (lastRequest) return runQuery(lastRequest);
}
function getNormalizedReq(): CheckDomainParams | undefined {
  const domain = extractDomain(req.value.domain);
  if (domain === "") {
    message.info(t("dns.check_domain.enter_domain"));
    return;
  }

  req.value.domain = domain;
  return {
    ...req.value,
    domain,
    apply_filter: false,
  };
}

async function syncRuleDetails(nextResult: CheckChainDnsResult) {
  config_rule.value = undefined;
  redirect_rule.value = undefined;

  if (nextResult.rule_id) {
    config_rule.value = createDnsRule(await getDnsRule(nextResult.rule_id));
  }
  if (nextResult.redirect_id) {
    redirect_rule.value = await get_dns_redirect(nextResult.redirect_id);
  }
}

async function applyResult(
  nextResult: CheckChainDnsResult,
  request: CheckDomainParams,
) {
  lastRequest = request;
  result.value = nextResult;
  await syncRuleDetails(nextResult);
}

async function query() {
  if (busy.value) return;
  const nextReq = getNormalizedReq();
  if (nextReq) await runQuery(nextReq);
}

async function runQuery(nextReq: CheckDomainParams) {
  loading.value = true;
  try {
    await applyResult(await check_domain(nextReq), nextReq);
  } finally {
    loading.value = false;
  }
}

async function deleteCache() {
  const nextReq = lastRequest;
  if (!nextReq || busy.value) {
    return;
  }

  deleteCacheLoading.value = true;
  try {
    await applyResult(await invalidate_domain_cache(nextReq), nextReq);
    message.success(t("dns.check_domain.delete_cache_success"));
  } finally {
    deleteCacheLoading.value = false;
  }
}

async function refreshCache() {
  const nextReq = lastRequest;
  if (!nextReq || busy.value || !isUpstreamResult.value) {
    return;
  }

  refreshCacheLoading.value = true;
  try {
    await applyResult(await refresh_domain_cache(nextReq), nextReq);
    message.success(t("dns.check_domain.refresh_cache_success"));
  } finally {
    refreshCacheLoading.value = false;
  }
}

async function quick_btn(record_type: LandscapeDnsRecordType, domain: string) {
  req.value.domain = domain;
  req.value.record_type = record_type;
  await query();
}
</script>

<template>
  <n-drawer
    @after-enter="init_req(true)"
    @after-leave="init_req(false)"
    v-model:show="show"
    width="500px"
    placement="right"
    :mask-closable="false"
  >
    <n-drawer-content
      :title="t('dns.check_domain.test_flow_query', { flow_id })"
      closable
    >
      <n-flex style="height: 100%" vertical>
        <div class="quick-queries" :style="{ '--label-ink': theme.textColor1 }">
          <div
            v-for="target in quickQueries"
            :key="target.name"
            class="quick-target"
          >
            <n-text depth="2" class="target-name">{{ target.name }}</n-text>
            <n-button-group size="small" :aria-label="target.name">
              <n-button
                v-for="preset in target.queries"
                :key="preset.type"
                class="quick-query"
                secondary
                :type="quickQueryButtonTypes[preset.type]"
                :disabled="busy"
                :aria-label="`${preset.label} ${target.name}`"
                @click="quick_btn(preset.type, preset.domain)"
              >
                <span class="query-label">{{ preset.label }}</span>
              </n-button>
            </n-button-group>
          </div>
        </div>
        <n-spin :show="loading">
          <n-input-group>
            <n-select
              :style="{ width: '33%' }"
              v-model:value="req.record_type"
              :options="options"
            />
            <n-input
              :placeholder="t('dns.check_domain.query_instruction')"
              @keyup.enter="query"
              v-model:value="req.domain"
            />

            <n-button
              :aria-label="t('dns.check_domain.run_query')"
              :disabled="busy"
              @click="query"
            >
              <template #icon>
                <n-icon>
                  <SearchLocate />
                </n-icon>
              </template>
            </n-button>
          </n-input-group>
          <n-text depth="3" class="diagnostic-hint">
            {{ t("dns.check_domain.diagnostic_hint") }}
          </n-text>
          <n-alert
            v-if="result?.query_filtered"
            type="warning"
            :show-icon="false"
            style="margin-top: 10px"
          >
            {{ t("dns.check_domain.query_filtered_hint") }}
          </n-alert>
        </n-spin>

        <n-scrollbar
          class="drawer-scroll-gutter"
          content-class="drawer-scroll-content"
        >
          <div v-if="result">
            <template v-if="config_rule">
              <h3>{{ t("dns.check_domain.matched_rule") }}</h3>
              <DnsRuleCard :rule="config_rule" @refresh="onRuleChanged" />
            </template>
            <template v-if="redirect_rule">
              <h3>{{ t("dns.check_domain.matched_redirect") }}</h3>
              <DnsRedirectCard :rule="redirect_rule" @refresh="refreshMatch" />
            </template>

            <div class="result-heading">
              <h3>{{ answerTitle }}</h3>
              <n-popconfirm
                v-if="isUpstreamResult"
                :positive-button-props="{ loading: refreshCacheLoading }"
                @positive-click="refreshCache"
              >
                <template #trigger>
                  <n-button size="small" type="warning" :disabled="busy">
                    {{ t("dns.check_domain.refresh_cache") }}
                  </n-button>
                </template>
                {{ t("dns.check_domain.confirm_refresh_cache") }}
              </n-popconfirm>
            </div>
            <DnsQueryRecords
              v-if="result.records?.length"
              :records="result.records"
            />
            <n-text v-else depth="3">{{
              t("dns.check_domain.no_records")
            }}</n-text>

            <template v-if="result.rule_id || result.cache_records != null">
              <div class="result-heading">
                <h3>{{ t("dns.check_domain.cache_result") }}</h3>
                <n-popconfirm
                  :positive-button-props="{ loading: deleteCacheLoading }"
                  @positive-click="deleteCache"
                >
                  <template #trigger>
                    <n-button size="small" :disabled="busy">
                      {{ t("dns.check_domain.delete_cache") }}
                    </n-button>
                  </template>
                  {{ t("dns.check_domain.confirm_delete_cache") }}
                </n-popconfirm>
              </div>
              <DnsQueryRecords
                v-if="result.cache_records?.length"
                :records="result.cache_records"
              />
              <n-text v-else depth="3">{{
                result.cache_records == null
                  ? t("dns.check_domain.cache_miss")
                  : t("dns.check_domain.no_records")
              }}</n-text>
            </template>
          </div>
        </n-scrollbar>
      </n-flex>
    </n-drawer-content>
  </n-drawer>
</template>

<style scoped>
.quick-queries {
  display: flex;
  gap: 8px;
}

.quick-target {
  display: grid;
  flex: 1 1 auto;
  gap: 4px;
}

.target-name {
  font-size: 12px;
}

.quick-query {
  flex: 1;
  padding-inline: 4px;
}

.query-label {
  color: color-mix(in srgb, currentColor 45%, var(--label-ink));
}

h3 {
  margin: 16px 0 6px;
  font-size: 14px;
}
.diagnostic-hint {
  display: block;
  margin-top: 10px;
}
.result-heading {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 16px 0 6px;
}
.result-heading h3 {
  min-width: 0;
  margin: 0;
}
</style>
