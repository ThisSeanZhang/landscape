<script setup lang="ts">
import { ref, computed } from "vue";
import { ChangeCatalog } from "@vicons/carbon";
import { trace_flow_match, trace_verdict } from "@/api/route/trace";
import { check_domain } from "@/api/dns_service";
import { reset_cache } from "@/api/route/cache";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";
import { useFrontEndStore } from "@/stores/front_end_config";
import FlowExhibit from "@/components/flow/FlowExhibit.vue";
import type { FlowMatchResult } from "@/api/route/trace";
import type { FlowVerdictResult } from "@/api/route/trace";
import { useI18n } from "vue-i18n";

const show = defineModel<boolean>("show", { required: true });

const enrolledDeviceStore = useEnrolledDeviceStore();
const frontEndStore = useFrontEndStore();
const { t } = useI18n();

// Step 1 state
const selectMode = ref(true);
const selectedDevice = ref<string | null>(null);
const srcIpv4 = ref("");
const srcIpv6 = ref("");
const srcMac = ref("");
const matchLoading = ref(false);
const matchResult = ref<FlowMatchResult | null>(null);

// Step 2 state
const queryMode = ref<"domain" | "ip">("domain");
const domainInput = ref("");
const ipInput = ref("");
const verdictLoading = ref(false);
const verdictResult = ref<FlowVerdictResult | null>(null);
const resolvedDomain = ref("");
const resetCacheLoading = ref(false);

// Whether current source has MAC (enables IPv6 queries)
const hasMac = computed(() => !!srcMac.value);

const deviceOptions = computed(() =>
  enrolledDeviceStore.bindings
    .filter((d) => d.ipv4 || d.mac)
    .map((d) => ({
      label: `${enrolledDeviceStore.GET_DISPLAY_NAME(d.mac)} (${frontEndStore.MASK_INFO(d.ipv4 || d.mac)})`,
      value: d.mac,
    })),
);

// Whether the flow match button should be enabled
const canMatch = computed(() => {
  return !!srcIpv4.value || !!srcIpv6.value || !!srcMac.value;
});

function onDeviceSelect(mac: string) {
  selectedDevice.value = mac;
  const device = enrolledDeviceStore.bindings.find((d) => d.mac === mac);
  if (device) {
    srcIpv4.value = device.ipv4 || "";
    srcIpv6.value = device.ipv6 || "";
    srcMac.value = device.mac || "";
  }
}

async function doFlowMatch() {
  if (!canMatch.value) return;
  matchLoading.value = true;
  matchResult.value = null;
  verdictResult.value = null;
  try {
    matchResult.value = await trace_flow_match({
      src_ipv4: srcIpv4.value || undefined,
      src_ipv6: srcIpv6.value || undefined,
      src_mac: srcMac.value || null,
    } as any);
  } finally {
    matchLoading.value = false;
  }
}

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

async function doVerdictByDomain() {
  if (!domainInput.value || !matchResult.value) return;
  const domain = extractDomain(domainInput.value);
  if (!domain) return;
  verdictLoading.value = true;
  verdictResult.value = null;
  resolvedDomain.value = domainInput.value.trim();
  try {
    const ips: string[] = [];

    // Query A records
    const dnsResultA = await check_domain({
      flow_id: matchResult.value.effective_flow_id,
      domain,
      record_type: "A" as any,
    });
    if (dnsResultA.records) {
      for (const r of dnsResultA.records) {
        if (r.rr_type === "A") {
          ips.push(r.data);
        }
      }
    }

    // Query AAAA records when MAC is present (IPv6 capable)
    if (hasMac.value) {
      try {
        const dnsResultAAAA = await check_domain({
          flow_id: matchResult.value.effective_flow_id,
          domain,
          record_type: "AAAA" as any,
        });
        if (dnsResultAAAA.records) {
          for (const r of dnsResultAAAA.records) {
            if (r.rr_type === "AAAA") {
              ips.push(r.data);
            }
          }
        }
      } catch {
        // AAAA query failure is non-fatal
      }
    }

    if (ips.length === 0) {
      window.$message?.warning(t("flow.trace.dns_no_records"));
      return;
    }

    verdictResult.value = await trace_verdict({
      flow_id: matchResult.value.effective_flow_id,
      src_ipv4: srcIpv4.value || undefined,
      src_ipv6: srcIpv6.value || undefined,
      dst_ips: ips,
    } as any);
  } finally {
    verdictLoading.value = false;
  }
}

async function doVerdictByIp() {
  if (!ipInput.value || !matchResult.value) return;
  verdictLoading.value = true;
  verdictResult.value = null;
  resolvedDomain.value = "";
  try {
    verdictResult.value = await trace_verdict({
      flow_id: matchResult.value.effective_flow_id,
      src_ipv4: srcIpv4.value || undefined,
      src_ipv6: srcIpv6.value || undefined,
      dst_ips: [ipInput.value],
    } as any);
  } finally {
    verdictLoading.value = false;
  }
}

async function doResetCache() {
  resetCacheLoading.value = true;
  try {
    await reset_cache();
    window.$message?.success(t("flow.trace.cache_cleared"));
  } finally {
    resetCacheLoading.value = false;
  }
}

function onOpen() {
  enrolledDeviceStore.UPDATE_INFO();
}

function formatAction(mark: { action: { t: string }; flow_id: number }) {
  switch (mark.action.t) {
    case "keep_going":
      return t("flow.trace.action_keep_going");
    case "direct":
      return t("flow.trace.action_direct");
    case "drop":
      return t("flow.trace.action_drop");
    case "redirect":
      return t("flow.trace.action_redirect", { flow_id: mark.flow_id });
    default:
      return mark.action.t;
  }
}

function actionTagType(
  mark: { action: { t: string } } | undefined,
): "default" | "info" | "success" | "warning" | "error" {
  if (!mark) return "default";
  switch (mark.action.t) {
    case "direct":
      return "success";
    case "drop":
      return "error";
    case "redirect":
      return "warning";
    default:
      return "info";
  }
}
</script>

<template>
  <n-drawer
    v-model:show="show"
    width="500px"
    placement="right"
    @after-enter="onOpen"
  >
    <n-drawer-content
      :title="t('flow.trace.title')"
      closable
      :native-scrollbar="false"
      body-content-style="padding: 14px 16px"
    >
      <n-flex vertical :size="16">
        <!-- Step 1: Source client -->
        <n-card size="small" :title="t('flow.trace.step1_title')">
          <n-flex vertical :size="8">
            <n-flex :wrap="false" align="center">
              <n-button size="small" @click="selectMode = !selectMode">
                <template #icon>
                  <n-icon><ChangeCatalog /></n-icon>
                </template>
              </n-button>
              <template v-if="selectMode">
                <n-select
                  :options="deviceOptions"
                  :value="selectedDevice"
                  @update:value="onDeviceSelect"
                  :placeholder="t('flow.trace.select_device_placeholder')"
                  clearable
                  filterable
                  style="flex: 1"
                />
              </template>
              <template v-else>
                <n-input
                  v-model:value="srcIpv4"
                  :placeholder="t('flow.trace.src_ipv4_optional')"
                  style="flex: 1"
                />
              </template>
            </n-flex>
            <template v-if="!selectMode">
              <n-input
                v-model:value="srcIpv6"
                :placeholder="t('flow.trace.src_ipv6_optional')"
              />
              <n-input
                v-model:value="srcMac"
                :placeholder="t('flow.trace.src_mac_optional')"
              />
            </template>
            <n-text
              v-if="selectMode && (srcIpv4 || srcMac)"
              depth="3"
              style="font-size: 12px"
            >
              IPv4: {{ srcIpv4 ? frontEndStore.MASK_INFO(srcIpv4) : t("flow.trace.none") }}
              &nbsp; IPv6:
              {{ srcIpv6 ? frontEndStore.MASK_INFO(srcIpv6) : t("flow.trace.none") }}
              &nbsp; MAC:
              {{ srcMac ? frontEndStore.MASK_INFO(srcMac) : t("flow.trace.none") }}
            </n-text>
            <n-button
              type="primary"
              :loading="matchLoading"
              :disabled="!canMatch"
              @click="doFlowMatch"
              block
              size="small"
            >
              {{ t("flow.trace.match_btn") }}
            </n-button>
          </n-flex>
        </n-card>

        <!-- Flow match result -->
        <n-card
          v-if="matchResult"
          size="small"
          :title="t('flow.trace.match_result_title')"
        >
          <n-descriptions
            :column="1"
            label-placement="left"
            bordered
            size="small"
          >
            <n-descriptions-item :label="t('flow.trace.mac_match')">
              <FlowExhibit
                v-if="matchResult.flow_id_by_mac != null"
                :flow_id="matchResult.flow_id_by_mac"
              />
              <n-tag v-else type="default" size="small">{{ t("flow.trace.no_match") }}</n-tag>
            </n-descriptions-item>
            <n-descriptions-item :label="t('flow.trace.ip_match')">
              <FlowExhibit
                v-if="matchResult.flow_id_by_ip != null"
                :flow_id="matchResult.flow_id_by_ip"
              />
              <n-tag v-else type="default" size="small">{{ t("flow.trace.no_match") }}</n-tag>
            </n-descriptions-item>
            <n-descriptions-item :label="t('flow.trace.effective_flow')">
              <n-tag
                v-if="matchResult.effective_flow_id === 0"
                type="info"
                size="small"
                >{{ t("flow.trace.default_flow") }}</n-tag
              >
              <FlowExhibit v-else :flow_id="matchResult.effective_flow_id" />
            </n-descriptions-item>
          </n-descriptions>
        </n-card>

        <!-- Step 2: Verdict query (shown after flow match) -->
        <template v-if="matchResult">
          <n-card size="small" :title="t('flow.trace.step2_title')">
            <n-flex vertical :size="8">
              <n-radio-group v-model:value="queryMode" size="small">
                <n-radio-button value="domain">{{
                  t("flow.trace.query_domain")
                }}</n-radio-button>
                <n-radio-button value="ip">{{ t("flow.trace.query_ip") }}</n-radio-button>
              </n-radio-group>

              <!-- Domain mode -->
              <template v-if="queryMode === 'domain'">
                <n-input
                  key="domain"
                  v-model:value="domainInput"
                  :placeholder="t('flow.trace.domain_placeholder')"
                />
                <n-button
                  type="primary"
                  :loading="verdictLoading"
                  :disabled="!domainInput"
                  @click="doVerdictByDomain"
                  block
                  size="small"
                >
                  {{ t("flow.trace.resolve_and_query") }}
                </n-button>
              </template>

              <!-- IP mode -->
              <template v-else>
                <n-input
                  key="ip"
                  v-model:value="ipInput"
                  :placeholder="t('flow.trace.target_ip_placeholder')"
                />
                <n-button
                  type="primary"
                  :loading="verdictLoading"
                  :disabled="!ipInput"
                  @click="doVerdictByIp"
                  block
                  size="small"
                >
                  {{ t("flow.trace.query_btn") }}
                </n-button>
              </template>
            </n-flex>
          </n-card>
        </template>

        <!-- Verdict results -->
        <template v-if="verdictResult">
          <n-flex v-if="resolvedDomain" align="center" justify="space-between">
            <n-text depth="3" style="font-size: 12px">
              {{
                t("flow.trace.domain_resolved_count", {
                  domain: resolvedDomain,
                  count: verdictResult.verdicts.length,
                })
              }}
            </n-text>
            <n-button
              size="tiny"
              tertiary
              type="warning"
              :loading="resetCacheLoading"
              @click="doResetCache"
            >
              {{ t("flow.trace.reset_route_cache") }}
            </n-button>
          </n-flex>
          <n-card
            v-for="(v, idx) in verdictResult.verdicts"
            :key="idx"
            size="small"
            :title="v.dst_ip"
          >
            <n-descriptions
              :column="1"
              label-placement="left"
              bordered
              size="small"
            >
              <n-descriptions-item :label="t('flow.trace.ip_rule')">
                <template v-if="v.ip_rule_match">
                  <n-flex align="center" :size="4">
                    <n-tag
                      :type="actionTagType(v.ip_rule_match.mark as any)"
                      size="small"
                    >
                      {{ formatAction(v.ip_rule_match.mark as any) }}
                    </n-tag>
                    <n-text depth="3" style="font-size: 12px">
                      {{
                        t("flow.trace.priority", {
                          priority: v.ip_rule_match.priority,
                        })
                      }}
                    </n-text>
                  </n-flex>
                </template>
                <n-tag v-else type="default" size="small">{{ t("flow.trace.no_match") }}</n-tag>
              </n-descriptions-item>
              <n-descriptions-item :label="t('flow.trace.dns_rule')">
                <template v-if="v.dns_rule_match">
                  <n-flex align="center" :size="4">
                    <n-tag
                      :type="actionTagType(v.dns_rule_match.mark as any)"
                      size="small"
                    >
                      {{ formatAction(v.dns_rule_match.mark as any) }}
                    </n-tag>
                    <n-text depth="3" style="font-size: 12px">
                      {{
                        t("flow.trace.priority", {
                          priority: v.dns_rule_match.priority,
                        })
                      }}
                    </n-text>
                  </n-flex>
                </template>
                <n-tag v-else type="default" size="small">{{ t("flow.trace.no_match") }}</n-tag>
              </n-descriptions-item>
              <n-descriptions-item :label="t('flow.trace.final_action')">
                <n-tag
                  v-if="!v.ip_rule_match && !v.dns_rule_match && !v.has_cache"
                  type="default"
                  size="small"
                >
                  {{ t("flow.trace.visit_first") }}
                </n-tag>
                <n-tag
                  v-else
                  :type="actionTagType(v.effective_mark as any)"
                  size="small"
                >
                  {{ formatAction(v.effective_mark as any) }}
                </n-tag>
              </n-descriptions-item>
              <n-descriptions-item :label="t('flow.trace.cache')">
                <template v-if="!v.has_cache">
                  <n-tag type="default" size="small">{{ t("flow.trace.no_cache") }}</n-tag>
                </template>
                <template v-else>
                  <n-tag
                    :type="v.cache_consistent ? 'success' : 'warning'"
                    size="small"
                  >
                    {{
                      v.cache_consistent
                        ? t("flow.trace.cache_consistent")
                        : t("flow.trace.cache_inconsistent")
                    }}
                  </n-tag>
                </template>
              </n-descriptions-item>
            </n-descriptions>
            <n-alert
              v-if="v.has_cache && !v.cache_consistent"
              type="warning"
              style="margin-top: 8px"
            >
              {{ t("flow.trace.cache_mismatch_alert") }}
            </n-alert>
          </n-card>
        </template>
      </n-flex>
    </n-drawer-content>
  </n-drawer>
</template>
