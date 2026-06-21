<script setup lang="ts">
import { useMessage } from "naive-ui";
import type {
  StaticNatMappingV4Config,
  StaticNatV4Target,
} from "@landscape-router/types/api/schemas";

import { computed, ref } from "vue";
import ConfigModal from "@/components/common/ConfigModal.vue";
import {
  get_static_nat_mapping_v4,
  push_static_nat_mapping_v4,
} from "@/api/static_nat_mapping";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";
import { useI18n } from "vue-i18n";

type Props = {
  rule_id?: string;
  initialFocusIndex?: number;
};

const props = defineProps<Props>();

const message = useMessage();
const { t } = useI18n();

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const origin_rule_json = ref<string>("");

const rule = ref<StaticNatMappingV4Config>();
const portInputRefs = ref<any[]>([]);

const enrolledDeviceStore = useEnrolledDeviceStore();
type TargetMode = "address" | "local" | "device";
const targetMode = ref<TargetMode>("device");
const selectedDeviceId = ref<string | null>(null);

const deviceOptions = computed(() =>
  enrolledDeviceStore.bindings.map((d) => ({
    label: `${d.name} (${d.mac})`,
    value: d.id!,
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

function syncTargetFormFromRule() {
  if (!rule.value) return;
  const target = rule.value.lan_target;
  targetMode.value = target?.t ?? "device";
  selectedDeviceId.value = target?.t === "device" ? target.device_id : null;
}

function syncRuleTarget() {
  if (!rule.value) return;
  if (targetMode.value === "local") {
    rule.value.lan_target = { t: "local" };
    return;
  }
  if (targetMode.value === "device") {
    rule.value.lan_target = selectedDeviceId.value
      ? { t: "device", device_id: selectedDeviceId.value }
      : { t: "device", device_id: "" };
    return;
  }
  rule.value.lan_target = {
    t: "address",
    ipv4:
      rule.value.lan_target?.t === "address" ? rule.value.lan_target.ipv4 : "",
  };
}

const addressTarget = computed<StaticNatV4Target & { t: "address" }>(() => {
  if (!rule.value?.lan_target || rule.value.lan_target.t !== "address") {
    return { t: "address", ipv4: "" };
  }
  return rule.value.lan_target as StaticNatV4Target & { t: "address" };
});

const selectedDevice = computed(() =>
  enrolledDeviceStore.bindings.find(
    (device) => device.id === selectedDeviceId.value,
  ),
);

const ipv4Pattern =
  /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;

const rules = {};

async function enter() {
  if (props.rule_id) {
    rule.value = await get_static_nat_mapping_v4(props.rule_id);
  } else {
    rule.value = {
      enable: true,
      mapping_pair_ports: [{ wan_port: 0, lan_port: 0 }],
      wan_iface_name: null,
      lan_target: { t: "device", device_id: "" },
      remark: "",
      l4_protocols: [6],
    };
  }
  syncTargetFormFromRule();
  origin_rule_json.value = JSON.stringify(rule.value);

  const focusIdx = props.initialFocusIndex;
  if (focusIdx !== undefined && focusIdx >= 0) {
    setTimeout(() => {
      const targetInput = portInputRefs.value[focusIdx];
      if (targetInput) {
        targetInput.focus();
        targetInput.$el?.scrollIntoView({
          behavior: "smooth",
          block: "center",
        });
      }
    }, 100);
  }
}

function addPortPair() {
  if (rule.value) {
    rule.value.mapping_pair_ports.push({ wan_port: 0, lan_port: 0 });
    setTimeout(() => {
      const index = rule.value!.mapping_pair_ports.length - 1;
      const input = portInputRefs.value[index];
      if (input) input.focus();
    }, 100);
  }
}

function removePortPair(index: number) {
  if (rule.value && rule.value.mapping_pair_ports.length > 1) {
    rule.value.mapping_pair_ports.splice(index, 1);
  }
}

const formRef = ref();

async function saveRule() {
  if (rule.value) {
    try {
      await formRef.value?.validate();

      if (rule.value.lan_target?.t === "address") {
        if (!rule.value.lan_target.ipv4) {
          message.error(t("nat.mapping.validation_ipv4_required"));
          return;
        }
        if (!ipv4Pattern.test(rule.value.lan_target.ipv4)) {
          message.error(t("nat.mapping.validation_ipv4"));
          return;
        }
      }

      if (rule.value.l4_protocols.length === 0) {
        message.error(t("nat.mapping.select_protocol_required"));
        return;
      }

      if (targetMode.value === "device" && !selectedDeviceId.value) {
        message.error(t("nat.mapping.select_device_required"));
        return;
      }

      commit_spin.value = true;
      syncRuleTarget();
      await push_static_nat_mapping_v4(rule.value);
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

const wanPortRule = {
  trigger: ["blur", "input"],
  validator(_ruleItem: any, value: number) {
    if (!value && value !== 0) return new Error(t("nat.mapping.required"));
    if (value <= 0 || value > 65535) return new Error(t("nat.mapping.range"));
    return true;
  },
};

const lanPortRule = {
  trigger: ["blur", "input"],
  validator(_ruleItem: any, value: number) {
    if (!value && value !== 0) return new Error(t("nat.mapping.required"));
    if (value <= 0 || value > 65535) return new Error(t("nat.mapping.range"));
    return true;
  },
};

const mappingPortsRule = {
  trigger: ["change"],
  validator(_ruleItem: any, value: any[]) {
    const ports = value || (rule.value ? rule.value.mapping_pair_ports : []);
    if (!ports || ports.length === 0) return true;

    const errors: string[] = [];
    const hasInvalid = ports.some(
      (p: any) =>
        !p.wan_port ||
        p.wan_port <= 0 ||
        p.wan_port > 65535 ||
        !p.lan_port ||
        p.lan_port <= 0 ||
        p.lan_port > 65535,
    );
    if (hasInvalid) errors.push(t("nat.mapping.invalid_port_value"));

    const wanPorts = ports.map((p: any) => p.wan_port);
    const hasDuplicateWan = wanPorts.length !== new Set(wanPorts).size;
    const lanPorts = ports.map((p: any) => p.lan_port);
    const hasDuplicateLan = lanPorts.length !== new Set(lanPorts).size;

    if (hasDuplicateWan || hasDuplicateLan) {
      errors.push(t("nat.mapping.duplicate_port_config"));
    }

    if (errors.length > 0) return new Error(errors.join(", "));
    return true;
  },
};
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

          <n-form-item-gi
            :span="2"
            :label="t('nat.mapping.port_mappings_label')"
            path="mapping_pair_ports"
            :rule="mappingPortsRule"
          >
            <n-flex vertical style="width: 100%; gap: 8px">
              <n-flex
                v-for="(pair, index) in rule.mapping_pair_ports"
                :key="index"
                align="center"
                style="gap: 8px"
              >
                <n-form-item
                  style="flex: 1; margin-bottom: 0"
                  :show-label="false"
                  :show-feedback="false"
                  :path="`mapping_pair_ports[${index}].wan_port`"
                  :rule="wanPortRule"
                >
                  <n-input-number
                    :ref="
                      (el: any) => {
                        if (el) portInputRefs[index] = el;
                      }
                    "
                    v-model:value="pair.wan_port"
                    :min="1"
                    :max="65535"
                    :placeholder="t('nat.mapping.public_port_placeholder')"
                    style="width: 100%"
                  />
                </n-form-item>
                <span style="color: #999">&rarr;</span>
                <n-form-item
                  style="flex: 1; margin-bottom: 0"
                  :show-label="false"
                  :show-feedback="false"
                  :path="`mapping_pair_ports[${index}].lan_port`"
                  :rule="lanPortRule"
                >
                  <n-input-number
                    v-model:value="pair.lan_port"
                    :min="1"
                    :max="65535"
                    :placeholder="t('nat.mapping.private_port_placeholder')"
                    style="width: 100%"
                  />
                </n-form-item>
                <n-button
                  v-if="rule.mapping_pair_ports.length > 1"
                  size="small"
                  @click="removePortPair(index)"
                  secondary
                  type="error"
                >
                  {{ t("nat.mapping.delete") }}
                </n-button>
              </n-flex>
              <n-button @click="addPortPair" dashed block size="small">
                {{ t("nat.mapping.add_port_pair") }}
              </n-button>
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
              <n-radio-button value="local">
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
            :label="t('nat.mapping.target_ipv4')"
          >
            <n-input
              :placeholder="t('nat.mapping.target_ipv4_hint')"
              :value="addressTarget.ipv4 || null"
              @update:value="
                (v: string | null) => {
                  if (rule) {
                    rule.lan_target = {
                      t: 'address',
                      ipv4: v || '',
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
                v-model:value="selectedDeviceId"
                :options="deviceOptions"
                :placeholder="t('nat.mapping.select_device_placeholder')"
                clearable
                filterable
                @update:value="syncRuleTarget"
              />
              <n-text v-if="selectedDevice" depth="3">
                {{ selectedDevice.iface_name || "-" }} /
                {{ selectedDevice.ipv4 || "-" }} /
                {{ selectedDevice.ipv6 || "-" }}
              </n-text>
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
