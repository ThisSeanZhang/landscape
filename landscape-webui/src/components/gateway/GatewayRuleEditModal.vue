<script setup lang="ts">
import { useMessage } from "naive-ui";
import type {
  HttpUpstreamRuleConfig,
  HttpUpstreamMatchRule,
  HttpUpstreamTarget,
  LoadBalanceMethod,
} from "@landscape-router/types/api/schemas";
import { computed, ref } from "vue";
import { get_gateway_rule, push_gateway_rule } from "@/api/gateway";
import { useI18n } from "vue-i18n";

type Props = {
  rule_id?: string;
};

const props = defineProps<Props>();

const message = useMessage();
const { t } = useI18n();

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const origin_rule_json = ref<string>("");
const rule = ref<HttpUpstreamRuleConfig>();
const commit_spin = ref(false);
const enable_health_check = ref(false);

const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_rule_json.value;
});

const matchTypeOptions = [
  { label: () => t("gateway.type_host"), value: "host" },
  { label: () => t("gateway.type_path_prefix"), value: "path_prefix" },
  { label: () => t("gateway.type_sni_proxy"), value: "sni_proxy" },
];

const lbOptions = [
  { label: () => t("gateway.lb_round_robin"), value: "round_robin" },
  { label: () => t("gateway.lb_random"), value: "random" },
  { label: () => t("gateway.lb_consistent"), value: "consistent" },
];

function defaultRule(): HttpUpstreamRuleConfig {
  return {
    enable: true,
    name: "",
    match_rule: { t: "host", domains: [""] },
    upstream: {
      targets: [{ address: "", port: 80, weight: 1, tls: false }],
      load_balance: "round_robin" as LoadBalanceMethod,
      health_check: null,
    },
  };
}

async function enter() {
  if (props.rule_id) {
    rule.value = await get_gateway_rule(props.rule_id);
  } else {
    rule.value = defaultRule();
  }
  enable_health_check.value = !!rule.value.upstream.health_check;
  origin_rule_json.value = JSON.stringify(rule.value);
}

function onMatchTypeChange(newType: string) {
  if (!rule.value) return;
  const current = rule.value.match_rule;
  if (current.t === newType) return;

  if (newType === "host") {
    rule.value.match_rule = { t: "host", domains: [""] };
  } else if (newType === "path_prefix") {
    rule.value.match_rule = { t: "path_prefix", prefix: "/" };
  } else if (newType === "sni_proxy") {
    rule.value.match_rule = { t: "sni_proxy", domains: [""] };
  }
}

function getDomains(): string[] {
  const mr = rule.value?.match_rule;
  if (mr && (mr.t === "host" || mr.t === "sni_proxy")) {
    return mr.domains;
  }
  return [];
}

function setDomain(index: number, value: string) {
  const mr = rule.value?.match_rule;
  if (mr && (mr.t === "host" || mr.t === "sni_proxy")) {
    mr.domains[index] = value;
  }
}

function addDomain() {
  const mr = rule.value?.match_rule;
  if (mr && (mr.t === "host" || mr.t === "sni_proxy")) {
    mr.domains.push("");
  }
}

function removeDomain(index: number) {
  const mr = rule.value?.match_rule;
  if (mr && (mr.t === "host" || mr.t === "sni_proxy")) {
    if (mr.domains.length > 1) {
      mr.domains.splice(index, 1);
    }
  }
}

function addTarget() {
  if (rule.value) {
    rule.value.upstream.targets.push({
      address: "",
      port: 80,
      weight: 1,
      tls: false,
    });
  }
}

function removeTarget(index: number) {
  if (rule.value && rule.value.upstream.targets.length > 1) {
    rule.value.upstream.targets.splice(index, 1);
  }
}

function onHealthCheckToggle(val: boolean) {
  if (!rule.value) return;
  if (val) {
    rule.value.upstream.health_check = {
      interval_secs: 10,
      timeout_secs: 5,
      healthy_threshold: 3,
      unhealthy_threshold: 3,
    };
  } else {
    rule.value.upstream.health_check = null;
  }
}

const formRef = ref();

async function saveRule() {
  if (!rule.value) return;
  try {
    await formRef.value?.validate();

    // Validate domains
    const mr = rule.value.match_rule;
    if (mr.t === "host" || mr.t === "sni_proxy") {
      const filtered = mr.domains.filter((d) => d.trim() !== "");
      if (filtered.length === 0) {
        message.error(t("gateway.domains_required"));
        return;
      }
      mr.domains = filtered;
    }

    // Validate targets
    const validTargets = rule.value.upstream.targets.filter(
      (t) => t.address.trim() !== "",
    );
    if (validTargets.length === 0) {
      message.error(t("gateway.target_required"));
      return;
    }
    rule.value.upstream.targets = validTargets;

    commit_spin.value = true;
    await push_gateway_rule(rule.value);
    show.value = false;
    emit("refresh");
  } catch (e) {
    console.error("Validation failed:", e);
  } finally {
    commit_spin.value = false;
  }
}
</script>

<template>
  <n-modal
    v-model:show="show"
    style="width: 640px"
    class="custom-card"
    preset="card"
    :title="t('gateway.edit_title')"
    @after-enter="enter"
    :bordered="false"
  >
    <n-flex vertical>
      <n-form v-if="rule" style="flex: 1" ref="formRef" :model="rule">
        <n-grid :cols="2" :x-gap="12">
          <n-form-item-gi :label="t('gateway.enabled')" :span="2">
            <n-switch v-model:value="rule.enable">
              <template #checked> {{ t("common.enable") }} </template>
              <template #unchecked> {{ t("common.disable") }} </template>
            </n-switch>
          </n-form-item-gi>

          <n-form-item-gi
            :label="t('gateway.name')"
            :span="2"
            path="name"
            :rule="{
              required: true,
              message: t('gateway.name_required'),
              trigger: ['blur'],
            }"
          >
            <n-input v-model:value="rule.name" />
          </n-form-item-gi>

          <n-form-item-gi :label="t('gateway.match_type')" :span="2">
            <n-radio-group
              :value="rule.match_rule.t"
              @update:value="onMatchTypeChange"
            >
              <n-radio-button
                v-for="opt in matchTypeOptions"
                :key="opt.value"
                :value="opt.value"
                :label="opt.label()"
              />
            </n-radio-group>
          </n-form-item-gi>

          <!-- Domains (for host / sni_proxy) -->
          <n-form-item-gi
            v-if="
              rule.match_rule.t === 'host' || rule.match_rule.t === 'sni_proxy'
            "
            :label="t('gateway.domains')"
            :span="2"
          >
            <n-flex vertical style="width: 100%; gap: 8px">
              <n-flex
                v-for="(domain, index) in getDomains()"
                :key="index"
                align="center"
                style="gap: 8px"
              >
                <n-input
                  :value="domain"
                  @update:value="(v: string) => setDomain(index, v)"
                  :placeholder="t('gateway.domain_placeholder')"
                  style="flex: 1"
                />
                <n-button
                  v-if="getDomains().length > 1"
                  size="small"
                  @click="removeDomain(index)"
                  secondary
                  type="error"
                >
                  {{ t("common.delete") }}
                </n-button>
              </n-flex>
              <n-button @click="addDomain" dashed block size="small">
                {{ t("gateway.add_domain") }}
              </n-button>
            </n-flex>
          </n-form-item-gi>

          <!-- Path prefix -->
          <n-form-item-gi
            v-if="rule.match_rule.t === 'path_prefix'"
            :label="t('gateway.path_prefix')"
            :span="2"
            :rule="{
              required: true,
              message: t('gateway.path_prefix_required'),
              trigger: ['blur'],
            }"
          >
            <n-input
              v-model:value="(rule.match_rule as any).prefix"
              :placeholder="t('gateway.path_prefix_placeholder')"
            />
          </n-form-item-gi>

          <n-divider style="margin: 4px 0; grid-column: span 2" />

          <!-- Upstream targets -->
          <n-form-item-gi :label="t('gateway.targets')" :span="2">
            <n-flex vertical style="width: 100%; gap: 8px">
              <n-flex
                v-for="(target, index) in rule.upstream.targets"
                :key="index"
                align="center"
                style="gap: 8px"
              >
                <n-input
                  v-model:value="target.address"
                  :placeholder="t('gateway.target_address')"
                  style="flex: 2"
                />
                <n-input-number
                  v-model:value="target.port"
                  :min="1"
                  :max="65535"
                  :placeholder="t('gateway.target_port')"
                  style="flex: 1"
                />
                <n-input-number
                  v-model:value="target.weight"
                  :min="1"
                  :max="100"
                  :placeholder="t('gateway.target_weight')"
                  style="width: 80px"
                />
                <n-switch v-model:value="target.tls" size="small">
                  <template #checked>TLS</template>
                  <template #unchecked>TLS</template>
                </n-switch>
                <n-button
                  v-if="rule.upstream.targets.length > 1"
                  size="small"
                  @click="removeTarget(index)"
                  secondary
                  type="error"
                >
                  {{ t("common.delete") }}
                </n-button>
              </n-flex>
              <n-button @click="addTarget" dashed block size="small">
                {{ t("gateway.add_target") }}
              </n-button>
            </n-flex>
          </n-form-item-gi>

          <n-form-item-gi :label="t('gateway.load_balance')" :span="2">
            <n-radio-group v-model:value="rule.upstream.load_balance">
              <n-radio-button
                v-for="opt in lbOptions"
                :key="opt.value"
                :value="opt.value"
                :label="opt.label()"
              />
            </n-radio-group>
          </n-form-item-gi>

          <n-divider style="margin: 4px 0; grid-column: span 2" />

          <!-- Health check -->
          <n-form-item-gi :label="t('gateway.health_check')" :span="2">
            <n-switch
              v-model:value="enable_health_check"
              @update:value="onHealthCheckToggle"
            >
              <template #checked> {{ t("common.enable") }} </template>
              <template #unchecked> {{ t("common.disable") }} </template>
            </n-switch>
          </n-form-item-gi>

          <template v-if="enable_health_check && rule.upstream.health_check">
            <n-form-item-gi :label="t('gateway.hc_interval')">
              <n-input-number
                v-model:value="rule.upstream.health_check.interval_secs"
                :min="1"
              />
            </n-form-item-gi>
            <n-form-item-gi :label="t('gateway.hc_timeout')">
              <n-input-number
                v-model:value="rule.upstream.health_check.timeout_secs"
                :min="1"
              />
            </n-form-item-gi>
            <n-form-item-gi :label="t('gateway.hc_healthy_threshold')">
              <n-input-number
                v-model:value="rule.upstream.health_check.healthy_threshold"
                :min="1"
              />
            </n-form-item-gi>
            <n-form-item-gi :label="t('gateway.hc_unhealthy_threshold')">
              <n-input-number
                v-model:value="rule.upstream.health_check.unhealthy_threshold"
                :min="1"
              />
            </n-form-item-gi>
          </template>
        </n-grid>
      </n-form>
    </n-flex>

    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{ t("common.cancel") }}</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveRule"
          :disabled="!isModified"
        >
          {{ t("common.save") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
