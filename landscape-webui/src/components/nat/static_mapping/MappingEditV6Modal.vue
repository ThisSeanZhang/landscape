<script setup lang="ts">
import { useMessage } from "naive-ui";
import type {
  StaticNatMappingV6Config,
  StaticNatV6Target,
} from "@landscape-router/types/api/schemas";

import { computed, ref } from "vue";
import ConfigModal from "@/components/common/ConfigModal.vue";
import {
  get_static_nat_mapping_v6,
  push_static_nat_mapping_v6,
} from "@/api/static_nat_mapping";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";
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

const rule = ref<StaticNatMappingV6Config>();

const enrolledDeviceStore = useEnrolledDeviceStore();
type TargetMode = "address" | "local" | "device";
const targetMode = ref<TargetMode>("device");
const selectedDeviceIds = ref<string[]>([]);

const deviceOptions = computed(() =>
  enrolledDeviceStore.bindings.map((d) => ({
    label: d.name,
    value: d.id!,
    disabled: !d.ipv6,
  })),
);

const commit_spin = ref(false);
const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_rule_json.value;
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

const savedPorts = ref<number[]>([]);

const portMode = computed<"all" | "ports">({
  get() {
    return rule.value?.port_config?.mode ?? "ports";
  },
  set(mode) {
    if (!rule.value) return;
    if (mode === "all") {
      if (targetMode.value === "local") {
        targetMode.value = "device";
        syncRuleTarget();
      }
      const pc = rule.value.port_config;
      if (pc?.mode === "ports") {
        savedPorts.value = pc.ports ?? [];
      }
      rule.value.port_config = { mode: "all" };
    } else {
      rule.value.port_config = { mode: "ports", ports: savedPorts.value };
    }
  },
});

const portTags = computed<string[]>({
  get() {
    const pc = rule.value?.port_config;
    return pc?.mode === "ports" ? (pc.ports ?? []).map(String) : [];
  },
  set(vals) {
    if (!rule.value) return;
    const cleaned = vals.filter((v) => {
      const n = parseInt(v, 10);
      return n >= 1 && n <= 65535 && String(n) === v.trim();
    });
    const deduped = [...new Set(cleaned)];
    if (cleaned.length < vals.length) {
      message.warning(t("nat.mapping.invalid_port_value"));
    }
    if (deduped.length < cleaned.length) {
      message.warning(t("nat.mapping.duplicate_port_config"));
    }
    rule.value.port_config = {
      mode: "ports",
      ports: deduped.map((v) => parseInt(v, 10)),
    };
  },
});

function syncTargetFormFromRule() {
  if (!rule.value) return;
  const target = rule.value.lan_target;
  targetMode.value = target?.t ?? "device";
  selectedDeviceIds.value =
    target?.t === "device" ? (target.device_ids ?? []) : [];
}

function syncRuleTarget() {
  if (!rule.value) return;
  if (targetMode.value === "local") {
    rule.value.lan_target = { t: "local" };
    return;
  }
  if (targetMode.value === "device") {
    rule.value.lan_target = {
      t: "device",
      device_ids: selectedDeviceIds.value,
    };
    return;
  }
  rule.value.lan_target = {
    t: "address",
    ipv6:
      rule.value.lan_target?.t === "address" ? rule.value.lan_target.ipv6 : "",
  };
}

const addressTarget = computed<StaticNatV6Target & { t: "address" }>(() => {
  if (!rule.value?.lan_target || rule.value.lan_target.t !== "address") {
    return { t: "address", ipv6: "" };
  }
  return rule.value.lan_target as StaticNatV6Target & { t: "address" };
});

const selectedDevices = computed(() =>
  enrolledDeviceStore.bindings.filter((d) =>
    selectedDeviceIds.value.includes(d.id!),
  ),
);

const ipv6Pattern =
  /^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)|(([0-9a-fA-F]{1,4}:){1,7}:)|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|(([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2})|(([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3})|(([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4})|(([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5})|([0-9a-fA-F]{1,4}:)((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

const rules = {};

async function enter() {
  savedPorts.value = [];
  if (props.rule_id) {
    rule.value = await get_static_nat_mapping_v6(props.rule_id);
  } else {
    rule.value = {
      enable: true,
      port_config: { mode: "ports", ports: [] },
      wan_iface_name: null,
      lan_target: { t: "device", device_ids: [] },
      remark: "",
      l4_protocols: [6],
    };
  }
  syncTargetFormFromRule();
  origin_rule_json.value = JSON.stringify(rule.value);
}

const formRef = ref();

async function saveRule() {
  if (rule.value) {
    try {
      await formRef.value?.validate();

      if (rule.value.lan_target?.t === "address") {
        if (!rule.value.lan_target.ipv6) {
          message.error(t("nat.mapping.validation_ipv6_required"));
          return;
        }
        if (!ipv6Pattern.test(rule.value.lan_target.ipv6)) {
          message.error(t("nat.mapping.validation_ipv6"));
          return;
        }
      }

      if (rule.value.l4_protocols.length === 0) {
        message.error(t("nat.mapping.select_protocol_required"));
        return;
      }

      if (
        targetMode.value === "device" &&
        selectedDeviceIds.value.length === 0
      ) {
        message.error(t("nat.mapping.select_device_required"));
        return;
      }

      if (
        targetMode.value === "device" &&
        selectedDevices.value.some((d) => !d.ipv6)
      ) {
        message.error(t("nat.mapping.device_ipv6_required"));
        return;
      }

      if (targetMode.value === "local" && portMode.value === "all") {
        message.error(t("nat.mapping.local_all_ports_disallowed"));
        return;
      }

      if (portMode.value === "ports" && portTags.value.length === 0) {
        message.error(t("nat.mapping.port_list_required"));
        return;
      }

      commit_spin.value = true;
      syncRuleTarget();
      await push_static_nat_mapping_v6(rule.value);
      show.value = false;
      emit("refresh");
    } catch (e) {
      console.error("Validation failed:", e);
    } finally {
      commit_spin.value = false;
    }
  }
}

const allProtocols = [6, 17];

const allSelected = computed({
  get() {
    if (!rule.value) return false;
    return (rule.value.l4_protocols || []).length === 2;
  },
  set(val: boolean) {
    if (!rule.value) return;
    rule.value.l4_protocols = val ? [...allProtocols] : [];
  },
});

const isIndeterminate = computed(() => {
  if (!rule.value) return false;
  const len = (rule.value.l4_protocols || []).length;
  return len > 0 && len < 2;
});
</script>

<template>
  <ConfigModal
    v-model:show="show"
    v-model:enabled="rule_enabled"
    :title="t('nat.mapping.edit_title')"
    :switch-disabled="!rule"
    width="600px"
    @after-enter="enter"
  >
    <n-flex vertical>
      <n-form
        v-if="rule"
        :rules="rules"
        style="flex: 1"
        ref="formRef"
        :model="rule"
        :cols="5"
      >
        <n-grid :cols="2">
          <n-form-item-gi :label="t('nat.mapping.allowed_protocols')" :span="2">
            <n-flex justify="space-between" style="flex: 1">
              <n-flex>
                <n-checkbox
                  v-model:checked="allSelected"
                  :indeterminate="isIndeterminate"
                >
                  {{ t("nat.mapping.select_all") }}
                </n-checkbox>
              </n-flex>
              <n-flex>
                <n-checkbox-group v-model:value="rule.l4_protocols">
                  <n-space item-style="display: flex;">
                    <n-checkbox :value="6" label="TCP" />
                    <n-checkbox :value="17" label="UDP" />
                  </n-space>
                </n-checkbox-group>
              </n-flex>
            </n-flex>
          </n-form-item-gi>

          <n-form-item-gi :span="2" :label="t('nat.mapping.port_config_label')">
            <n-flex vertical style="width: 100%; gap: 8px">
              <n-radio-group v-model:value="portMode">
                <n-radio-button value="ports">
                  {{ t("nat.mapping.port_mode_specific") }}
                </n-radio-button>
                <n-radio-button value="all" :disabled="targetMode === 'local'">
                  {{ t("nat.mapping.port_mode_all") }}
                </n-radio-button>
              </n-radio-group>

              <n-dynamic-tags
                v-if="portMode === 'ports'"
                v-model:value="portTags"
                :input-style="{ width: '100px' }"
              />

              <n-alert
                v-if="portMode === 'all'"
                type="success"
                :show-icon="false"
                style="width: 100%"
              >
                {{ t("nat.mapping.port_mode_all_hint") }}
              </n-alert>
            </n-flex>
          </n-form-item-gi>

          <n-form-item-gi :span="2" :label="t('nat.mapping.target_type')">
            <n-radio-group
              v-model:value="targetMode"
              @update:value="syncRuleTarget"
            >
              <n-radio-button value="device">
                {{ t("nat.mapping.target_type_device") }}
              </n-radio-button>
              <n-radio-button value="local" :disabled="portMode === 'all'">
                {{ t("nat.mapping.target_type_local") }}
              </n-radio-button>
              <n-radio-button value="address">
                {{ t("nat.mapping.target_type_address") }}
              </n-radio-button>
            </n-radio-group>
          </n-form-item-gi>

          <n-form-item-gi
            v-if="targetMode === 'address'"
            :span="2"
            :label="t('nat.mapping.target_ipv6')"
          >
            <n-input
              :placeholder="t('nat.mapping.target_ipv6_hint')"
              :value="addressTarget.ipv6 || null"
              @update:value="
                (v: string | null) => {
                  if (rule) {
                    rule.lan_target = {
                      t: 'address',
                      ipv6: v || '',
                    };
                    syncRuleTarget();
                  }
                }
              "
            />
          </n-form-item-gi>

          <n-form-item-gi
            v-if="targetMode === 'local'"
            :span="2"
            :label="t('nat.mapping.target_local')"
          >
            <n-alert type="info" :show-icon="false" style="width: 100%">
              {{ t("nat.mapping.target_local_hint") }}
            </n-alert>
          </n-form-item-gi>

          <n-form-item-gi
            v-if="targetMode === 'device'"
            :span="2"
            :label="t('nat.mapping.target_device')"
          >
            <n-flex vertical style="width: 100%">
              <n-select
                v-model:value="selectedDeviceIds"
                :options="deviceOptions"
                :placeholder="t('nat.mapping.select_device_placeholder')"
                clearable
                filterable
                multiple
                @update:value="syncRuleTarget"
              />
            </n-flex>
          </n-form-item-gi>

          <n-form-item-gi :span="2" :label="t('nat.mapping.remark')">
            <n-input v-model:value="rule.remark" type="textarea" />
          </n-form-item-gi>
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
  </ConfigModal>
</template>
