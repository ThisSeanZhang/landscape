<script setup lang="ts">
import {
  getFlowRule,
  addFlowRule,
} from "@landscape-router/types/api/flow-rules/flow-rules";
import { useMessage } from "naive-ui";
import { computed } from "vue";
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import ConfigModal from "@/components/common/ConfigModal.vue";
import FlowMatchRule from "./match/FlowMatchRule.vue";
import { flow_config_default } from "@/lib/default_value";
import type {
  ApiFlowConfig as FlowConfig,
  FlowEntryRule,
  ApiWeightedFlowTarget as WeightedFlowTarget,
} from "@landscape-router/types/api/schemas";
import { useFrontEndStore } from "@/stores/front_end_config";
interface Props {
  rule_id?: string;
}

const props = defineProps<Props>();

const frontEndStore = useFrontEndStore();

const message = useMessage();
const { t } = useI18n();

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const rule_json = ref("");
const rule = ref<FlowConfig>();

const commit_spin = ref(false);
const isModified = computed(() => {
  return JSON.stringify(rule.value) !== rule_json.value;
});

const rule_enabled = computed({
  get() {
    return rule.value?.enable ?? false;
  },
  set(value: boolean) {
    if (rule.value) {
      rule.value.enable = value;
    }
  },
});

const ordered_targets = computed(
  () =>
    !!rule.value?.failover?.enable ||
    rule.value?.failover?.mode === "primary_backup",
);
const failover_enabled = computed({
  get: () => rule.value?.failover?.enable ?? false,
  set: (enable: boolean) => {
    if (!rule.value) return;
    rule.value.failover = {
      ...rule.value.failover,
      mode: "primary_backup",
      enable,
      auto_failback: rule.value.failover?.auto_failback ?? true,
    };
  },
});
function restoreWeightedMode() {
  if (rule.value?.failover) {
    rule.value.failover.bind_default_flow = false;
    rule.value.failover.bind_router_traffic = false;
    rule.value.failover.mode = "weighted";
    rule.value.failover.enable = false;
  }
}

async function enter() {
  if (props.rule_id) {
    rule.value = await getFlowRule(props.rule_id);
  } else {
    rule.value = flow_config_default();
  }

  rule.value.failover = {
    bind_default_flow: false,
    bind_router_traffic: false,
    trigger: "health_check",
    unknown_grace_secs: 30,
    fail_open_on_unknown: false,
    failback_delay_secs: 30,
    switch_hold_secs: 5,
    failure_connection_policy: "reset_existing",
    recovery_connection_policy: "new_connections_only",
    enable: false,
    auto_failback: true,
    ...rule.value.failover,
  };
  rule.value.flow_targets = normalizeFlowTargets(rule.value.flow_targets);

  rule_json.value = JSON.stringify(rule.value);
}

function exit() {
  rule.value = flow_config_default();
  rule_json.value = JSON.stringify(rule.value);
}

function findDuplicateEntryRules(rules: FlowEntryRule[]): string | null {
  const seen = new Set<string>();
  for (const rule of rules) {
    let key: string;
    if (rule.mode.t === "mac") {
      key = `mac:${rule.mode.mac_addr.toLowerCase()}`;
    } else if (rule.mode.t === "ip") {
      key = `ip:${rule.mode.ip}/${rule.mode.prefix_len}`;
    } else {
      key = `device:${rule.mode.device_id}`;
    }
    if (seen.has(key)) {
      return key;
    }
    seen.add(key);
  }
  return null;
}

async function saveRule() {
  if (!rule.value) {
    return;
  }

  rule.value.failover = {
    bind_default_flow: false,
    bind_router_traffic: false,
    trigger: "health_check",
    unknown_grace_secs: 30,
    fail_open_on_unknown: false,
    failback_delay_secs: 30,
    switch_hold_secs: 5,
    failure_connection_policy: "reset_existing",
    recovery_connection_policy: "new_connections_only",
    enable: false,
    auto_failback: true,
    ...rule.value.failover,
  };
  rule.value.flow_targets = normalizeFlowTargets(rule.value.flow_targets);

  if (rule.value.flow_id == -1) {
    message.warning(t("flow.edit.duplicate_id_warning"));
    return;
  }

  if (rule.value.flow_id === 0) {
    message.warning(t("flow.edit.reserved_id_warning"));
    return;
  }

  if (
    !ordered_targets.value &&
    rule.value.flow_targets.length > 0 &&
    rule.value.flow_targets.every((target) => (target.weight ?? 1) === 0)
  ) {
    message.warning(t("flow.edit.all_zero_weight_warning"));
    return;
  }

  if (ordered_targets.value) {
    const ids = rule.value.flow_targets.map((entry) =>
      entry.target.t === "interface" ? entry.target.link_id : "",
    );
    if (
      ids.length < (rule.value.failover?.enable ? 2 : 1) ||
      ids.includes("") ||
      new Set(ids).size !== ids.length
    ) {
      message.warning(t("flow.failover.invalid_targets"));
      return;
    }
  }
  const dup = findDuplicateEntryRules(rule.value.flow_match_rules);
  if (dup) {
    message.warning(t("flow.edit.duplicate_entry_warning", { dup }));
    return;
  }

  try {
    commit_spin.value = true;
    await addFlowRule(rule.value);
    console.log("submit success");
    show.value = false;
  } catch (_e: any) {
    // Error message already shown by axios interceptor
  } finally {
    commit_spin.value = false;
  }
  emit("refresh");
}

function normalizeFlowTargets(
  flowTargets: WeightedFlowTarget[],
): WeightedFlowTarget[] {
  return flowTargets.map((target) => ({
    ...target,
    weight: target.weight ?? 1,
  }));
}
</script>

<template>
  <ConfigModal
    v-model:show="show"
    v-model:enabled="rule_enabled"
    :title="t('flow.edit.title')"
    :switch-disabled="!rule"
    width="600px"
    @after-enter="enter"
    @after-leave="exit"
  >
    <!-- {{ rule }} -->
    <n-form v-if="rule" style="flex: 1" ref="formRef" :model="rule" :cols="5">
      <n-grid :cols="5" :x-gap="10">
        <n-form-item-gi :label="t('flow.edit.flow_id_label')" :span="2">
          <n-input-number
            :min="1"
            :max="255"
            v-model:value="rule.flow_id"
            clearable
          />
        </n-form-item-gi>
        <n-form-item-gi :span="3" :label="t('flow.edit.name')">
          <n-input
            :type="frontEndStore.presentation_mode ? 'password' : 'text'"
            v-model:value="rule.name"
            :placeholder="t('flow.edit.name_placeholder')"
          />
        </n-form-item-gi>
        <n-form-item-gi :span="5" :label="t('flow.edit.remark')">
          <n-input
            :type="frontEndStore.presentation_mode ? 'password' : 'text'"
            v-model:value="rule.remark"
          />
        </n-form-item-gi>
      </n-grid>
      <n-form-item>
        <template #label>
          <Notice
            >{{ t("flow.edit.entry_rules_title") }}
            <template #msg>
              {{ t("flow.edit.entry_rules_desc_1") }}<br />
              {{ t("flow.edit.entry_rules_desc_2") }}<br />
              {{ t("flow.edit.entry_rules_desc_3") }}
            </template>
          </Notice>
        </template>
        <FlowMatchRule v-model:match_rules="rule.flow_match_rules">
        </FlowMatchRule>
      </n-form-item>
      <n-form-item v-if="rule.failover" :label="t('flow.failover.enable')">
        <n-switch v-model:value="failover_enabled" />
      </n-form-item>
      <n-form-item
        v-if="rule.failover?.enable"
        :label="t('flow.failover.trigger')"
      >
        <n-select
          v-model:value="rule.failover.trigger"
          :options="[
            { label: t('flow.failover.trigger_health'), value: 'health_check' },
            { label: t('flow.failover.trigger_link'), value: 'link_state' },
          ]"
        />
      </n-form-item>
      <n-alert
        v-if="rule.failover?.enable && rule.failover.trigger === 'link_state'"
        type="info"
        :show-icon="false"
        style="margin-bottom: 16px"
      >
        {{ t("flow.failover.link_hint") }}
      </n-alert>
      <n-form-item
        v-if="rule.failover?.enable"
        :label="t('flow.failover.auto_failback')"
      >
        <n-switch v-model:value="rule.failover.auto_failback" />
      </n-form-item>
      <n-collapse
        v-if="rule.failover && ordered_targets"
        style="margin-bottom: 16px"
      >
        <n-collapse-item
          :title="t('flow.failover.advanced')"
          name="failover-advanced"
        >
          <n-form-item :label="t('flow.failover.bind_default')">
            <n-switch
              v-model:value="rule.failover.bind_default_flow"
              @update:value="
                !$event && (rule.failover.bind_router_traffic = false)
              "
            />
          </n-form-item>
          <n-form-item :label="t('flow.failover.bind_router')">
            <n-switch
              v-model:value="rule.failover.bind_router_traffic"
              :disabled="!rule.failover.bind_default_flow"
            />
          </n-form-item>
          <n-text depth="3">{{ t("flow.failover.binding_hint") }}</n-text>
          <n-form-item
            v-if="rule.failover.trigger !== 'link_state'"
            :label="t('flow.failover.unknown_grace')"
            ><n-input-number
              v-model:value="rule.failover.unknown_grace_secs"
              :min="0"
              :max="600"
              :clearable="false"
          /></n-form-item>
          <n-form-item
            v-if="rule.failover.trigger !== 'link_state'"
            :label="t('flow.failover.fail_open')"
            ><n-switch v-model:value="rule.failover.fail_open_on_unknown"
          /></n-form-item>
          <n-form-item :label="t('flow.failover.failback_delay')"
            ><n-input-number
              v-model:value="rule.failover.failback_delay_secs"
              :min="0"
              :max="3600"
              :clearable="false"
          /></n-form-item>
          <n-form-item :label="t('flow.failover.switch_hold')"
            ><n-input-number
              v-model:value="rule.failover.switch_hold_secs"
              :min="0"
              :max="3600"
              :clearable="false"
          /></n-form-item>
          <n-form-item
            v-for="key in [
              'failure_connection_policy',
              'recovery_connection_policy',
            ] as const"
            :key="key"
            :label="t(`flow.failover.${key}`)"
          >
            <n-select
              v-model:value="rule.failover[key]"
              :options="[
                {
                  label: t('flow.failover.new_connections_only'),
                  value: 'new_connections_only',
                },
                {
                  label: t('flow.failover.reset_existing'),
                  value: 'reset_existing',
                },
              ]"
            />
          </n-form-item>
          <n-text depth="3">{{ t("flow.failover.connection_limits") }}</n-text>
          <n-alert
            v-if="
              rule.failover.failure_connection_policy === 'new_connections_only'
            "
            type="warning"
          >
            {{ t("flow.failover.failed_connection_warning") }}
          </n-alert>
        </n-collapse-item>
      </n-collapse>
      <n-alert v-if="ordered_targets" type="info" style="margin-bottom: 16px">{{
        t("flow.failover.hint")
      }}</n-alert>
      <n-button
        v-if="ordered_targets && !rule.failover?.enable"
        text
        type="primary"
        style="margin-bottom: 16px"
        @click="restoreWeightedMode"
        >{{ t("flow.failover.restore_weighted") }}</n-button
      >
      <n-form-item label="">
        <template #label>
          <Notice>
            {{ t("flow.edit.target_rules_title") }}
            <template #msg>
              {{ t("flow.edit.target_rules_desc_1") }}<br />
              {{ t("flow.edit.target_rules_desc_2") }}
            </template>
          </Notice>
        </template>

        <FlowTargetRule
          v-model:target_rules="rule.flow_targets"
          :failover="ordered_targets"
        >
        </FlowTargetRule>
      </n-form-item>
    </n-form>
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
  </ConfigModal>
</template>
