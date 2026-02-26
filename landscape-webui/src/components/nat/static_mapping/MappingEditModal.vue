<script setup lang="ts">
import { useMessage } from "naive-ui";
import type { StaticNatMappingConfig } from "@landscape-router/types/api/schemas";

import { computed, ref } from "vue";
import {
  get_static_nat_mapping,
  push_static_nat_mapping,
} from "@/api/static_nat_mapping";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";
import { ChangeCatalog } from "@vicons/carbon";
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

const rule = ref<StaticNatMappingConfig>();
const portInputRefs = ref<any[]>([]); // Array to store input refs

const enrolledDeviceStore = useEnrolledDeviceStore();
const ipv4SelectMode = ref(true);

const deviceIpv4Options = computed(() =>
  enrolledDeviceStore.bindings
    .filter((d) => d.ipv4)
    .map((d) => ({
      label: `${d.name} (${d.ipv4})`,
      value: d.ipv4!,
    })),
);

const commit_spin = ref(false);
const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_rule_json.value;
});

const rules = {
  lan_ipv4: [
    {
      pattern:
        /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/,
      message: t("nat.mapping.validation_ipv4"),
      trigger: ["blur", "input"],
    },
  ],
  lan_ipv6: [
    {
      pattern:
        /^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)|(([0-9a-fA-F]{1,4}:){1,7}:)|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|(([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2})|(([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3})|(([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4})|(([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5})|([0-9a-fA-F]{1,4}:)((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/,
      message: t("nat.mapping.validation_ipv6"),
      trigger: ["blur", "input"],
    },
  ],
};

async function enter() {
  if (props.rule_id) {
    rule.value = await get_static_nat_mapping(props.rule_id);
  } else {
    rule.value = {
      enable: true,
      mapping_pair_ports: [{ wan_port: 0, lan_port: 0 }],
      wan_iface_name: null,
      lan_ipv4: null,
      lan_ipv6: null,
      remark: "",
      ipv4_l4_protocol: [6],
      ipv6_l4_protocol: [],
    };
  }
  origin_rule_json.value = JSON.stringify(rule.value);

  // Handle auto-focus on specific port index
  const focusIdx = props.initialFocusIndex;
  if (focusIdx !== undefined && focusIdx >= 0) {
    // Small delay to ensure rendering is complete
    setTimeout(() => {
      const targetInput = portInputRefs.value[focusIdx];
      if (targetInput) {
        targetInput.focus();
        // Optional: scroll into view if the list is long
        targetInput.$el?.scrollIntoView({
          behavior: "smooth",
          block: "center",
        });
      }
    }, 100);
  }
}

// Functions to manage port pairs
function addPortPair() {
  if (rule.value) {
    rule.value.mapping_pair_ports.push({ wan_port: 0, lan_port: 0 });
    // Focus the new input in next tick
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
      // Validate form
      await formRef.value?.validate();

      if (
        rule.value.ipv4_l4_protocol.length === 0 &&
        rule.value.ipv6_l4_protocol.length === 0
      ) {
        message.error(t("nat.mapping.select_protocol_required"));
        return;
      }

      commit_spin.value = true;
      if (rule.value.lan_ipv4 === "") rule.value.lan_ipv4 = null;
      if (rule.value.lan_ipv6 === "") rule.value.lan_ipv6 = null;
      await push_static_nat_mapping(rule.value);
      console.log("submit success");
      show.value = false;
      emit("refresh");
    } catch (e) {
      console.error("Validation failed:", e);
    } finally {
      commit_spin.value = false;
    }
  }
}

// async function export_config() {
//   let configs = rule.value.source;
//   await copy_context_to_clipboard(message, JSON.stringify(configs, null, 2));
// }

// async function import_rules() {
//   try {
//     let rules = JSON.parse(await read_context_from_clipboard());
//     rule.value.source = rules;
//   } catch (e) {}
// }

const allProtocols = [6, 17]; // Supported protocols
const totalSelectable = allProtocols.length * 2; // 4

const allSelected = computed({
  get() {
    if (!rule.value) return false;
    const selected = [
      ...(rule.value.ipv4_l4_protocol || []),
      ...(rule.value.ipv6_l4_protocol || []),
    ];
    return selected.length === totalSelectable;
  },
  set(val: boolean) {
    if (!rule.value) return;
    if (val) {
      rule.value.ipv4_l4_protocol = [...allProtocols];
      rule.value.ipv6_l4_protocol = [...allProtocols];
    } else {
      rule.value.ipv4_l4_protocol = [];
      rule.value.ipv6_l4_protocol = [];
    }
  },
});

const isIndeterminate = computed(() => {
  if (!rule.value) return false;
  const selected = [
    ...(rule.value.ipv4_l4_protocol || []),
    ...(rule.value.ipv6_l4_protocol || []),
  ];
  return selected.length > 0 && selected.length < totalSelectable;
});

// Port validation rules
const wanPortRule = {
  trigger: ["blur", "input"],
  validator(ruleItem: any, value: number) {
    if (!value && value !== 0) return new Error(t("nat.mapping.required"));
    if (value <= 0 || value > 65535) return new Error(t("nat.mapping.range"));
    return true;
  },
};

const lanPortRule = {
  trigger: ["blur", "input"],
  validator(ruleItem: any, value: number) {
    if (!value && value !== 0) return new Error(t("nat.mapping.required"));
    if (value <= 0 || value > 65535) return new Error(t("nat.mapping.range"));
    return true;
  },
};

// Aggregate list validation rule (for summarized error output)
const mappingPortsRule = {
  trigger: ["change"], // Listen for list changes
  validator(ruleItem: any, value: any[]) {
    // Value can be empty if path binding fails or update is not triggered yet.
    // n-form-item with path="mapping_pair_ports" should provide this array.

    // Fallback to current model when validator value is empty.
    const ports = value || (rule.value ? rule.value.mapping_pair_ports : []);
    if (!ports || ports.length === 0) return true;

    // Collect all validation issues.
    const errors: string[] = [];

    // Check invalid ranges/empty values.
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

    // Check duplicate mappings.
    const wanPorts = ports.map((p: any) => p.wan_port);
    const hasDuplicateWan = wanPorts.length !== new Set(wanPorts).size;

    const lanPorts = ports.map((p: any) => p.lan_port);
    const hasDuplicateLan = lanPorts.length !== new Set(lanPorts).size;

    if (hasDuplicateWan || hasDuplicateLan) {
      errors.push(t("nat.mapping.duplicate_port_config"));
    }

    if (errors.length > 0) {
      return new Error(errors.join(", "));
    }

    return true;
  },
};
</script>

<template>
  <n-modal
    v-model:show="show"
    style="width: 600px"
    class="custom-card"
    preset="card"
    :title="t('nat.mapping.edit_title')"
    @after-enter="enter"
    :bordered="false"
  >
    <n-flex vertical>
      <!-- {{ isModified }} -->
      <n-form
        v-if="rule"
        :rules="rules"
        style="flex: 1"
        ref="formRef"
        :model="rule"
        :cols="5"
      >
        <n-grid :cols="2">
          <!-- <n-form-item-gi label="Priority" :span="2">
          <n-input-number v-model:value="rule.index" clearable />
        </n-form-item-gi> -->
          <n-form-item-gi :label="t('nat.mapping.enabled')" :span="2">
            <n-switch v-model:value="rule.enable">
              <template #checked> {{ t("nat.mapping.enabled_yes") }} </template>
              <template #unchecked>
                {{ t("nat.mapping.enabled_no") }}
              </template>
            </n-switch>
          </n-form-item-gi>

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
                <n-checkbox-group v-model:value="rule.ipv4_l4_protocol">
                  <n-space item-style="display: flex;">
                    <n-checkbox :value="6" label="TCP v4" />
                    <n-checkbox :value="17" label="UDP v4" />
                  </n-space>
                </n-checkbox-group>
              </n-flex>
              <n-flex>
                <n-checkbox-group v-model:value="rule.ipv6_l4_protocol">
                  <n-space item-style="display: flex;">
                    <n-checkbox :value="6" label="TCP v6" />
                    <n-checkbox :value="17" label="UDP v6" />
                  </n-space>
                </n-checkbox-group>
              </n-flex>
            </n-flex>
          </n-form-item-gi>

          <!-- <n-form-item-gi :span="5" label="Ingress WAN">
          <n-radio-group v-model:value="rule.wan_iface_name" name="filter">
            <n-radio-button
              v-for="opt in get_dns_filter_options()"
              :key="opt.value"
              :value="opt.value"
              :label="opt.label"
            />
          </n-radio-group>
        </n-form-item-gi> -->

          <!-- Port mapping pair list -->
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
                <span style="color: #999">→</span>
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

          <n-form-item-gi
            :span="2"
            path="lan_ipv4"
            :label="t('nat.mapping.target_ipv4')"
          >
            <n-flex :wrap="false" style="flex: 1">
              <n-button @click="ipv4SelectMode = !ipv4SelectMode">
                <n-icon><ChangeCatalog /></n-icon>
              </n-button>
              <n-select
                v-if="ipv4SelectMode"
                :options="deviceIpv4Options"
                :value="rule.lan_ipv4 || null"
                @update:value="
                  (v: string) => {
                    if (rule) rule.lan_ipv4 = v;
                  }
                "
                :placeholder="t('nat.mapping.select_device_placeholder')"
                clearable
                filterable
                style="flex: 1"
              />
              <n-input
                v-else
                :placeholder="t('nat.mapping.target_ipv4_hint')"
                v-model:value="rule.lan_ipv4"
              />
            </n-flex>
          </n-form-item-gi>

          <n-form-item-gi
            :span="2"
            path="lan_ipv6"
            :label="t('nat.mapping.target_ipv6')"
          >
            <n-input
              :placeholder="t('nat.mapping.target_ipv6_hint')"
              v-model:value="rule.lan_ipv6"
            />
          </n-form-item-gi>

          <n-form-item-gi :span="2" :label="t('nat.mapping.remark')">
            <n-input v-model:value="rule.remark" type="textarea" />
          </n-form-item-gi>
        </n-grid>
      </n-form>
    </n-flex>

    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{ t("nat.mapping.cancel") }}</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveRule"
          :disabled="!isModified"
        >
          {{ t("nat.mapping.save") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
