<script setup lang="ts">
import { useMessage } from "naive-ui";
import { StaticNatMappingConfig } from "@/rust_bindings/common/nat";

import { computed } from "vue";
import { ref } from "vue";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";
import {
  get_static_nat_mapping,
  push_static_nat_mapping,
} from "@/api/static_nat_mapping";

type Props = {
  rule_id?: string;
};

const props = defineProps<Props>();

const message = useMessage();

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const origin_rule_json = ref<string>("");

const rule = ref<StaticNatMappingConfig>();

const commit_spin = ref(false);
const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_rule_json.value;
});

const rules = {
  wan_port: [
    {
      required: true,
      type: "number",
      message: "开放端口不能为空",
      trigger: ["blur", "input"],
    },
    {
      validator(rule: any, value: number) {
        if (value <= 0) {
          return new Error("开放端口必须大于 0");
        }
        if (value > 65535) {
          return new Error("开放端口必须小于等于 65535");
        }
        return true;
      },
      trigger: ["blur", "input"],
    },
  ],
  lan_port: [
    {
      required: true,
      type: "number",
      message: "内网目标端口不能为空",
      trigger: ["blur", "input"],
    },
    {
      validator(rule: any, value: number) {
        if (value <= 0) {
          return new Error("内网目标端口必须大于 0");
        }
        if (value > 65535) {
          return new Error("内网目标端口必须小于等于 65535");
        }
        return true;
      },
      trigger: ["blur", "input"],
    },
  ],
  lan_ipv4: [
    {
      pattern:
        /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/,
      message: "请输入合法的 IPv4 地址",
      trigger: ["blur", "input"],
    },
  ],
  lan_ipv6: [
    {
      pattern:
        /^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)|(([0-9a-fA-F]{1,4}:){1,7}:)|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|(([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2})|(([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3})|(([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4})|(([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5})|([0-9a-fA-F]{1,4}:)((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/,
      message: "请输入合法的 IPv6 地址",
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
      wan_port: 0,
      wan_iface_name: null,
      lan_port: 0,
      lan_ipv4: null,
      lan_ipv6: null,
      remark: "",
      ipv4_l4_protocol: [6],
      ipv6_l4_protocol: [],
    };
  }
  origin_rule_json.value = JSON.stringify(rule.value);
}

const formRef = ref();

async function saveRule() {
  if (rule.value) {
    try {
      await formRef.value?.validate();
      commit_spin.value = true;
      if (rule.value.lan_ipv4 === "") rule.value.lan_ipv4 = null;
      if (rule.value.lan_ipv6 === "") rule.value.lan_ipv6 = null;
      await push_static_nat_mapping(rule.value);
      console.log("submit success");
      show.value = false;
      emit("refresh");
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

const allProtocols = [6, 17]; // 可选协议
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
</script>

<template>
  <n-modal
    v-model:show="show"
    style="width: 600px"
    class="custom-card"
    preset="card"
    title="规则编辑"
    @after-enter="enter"
    :bordered="false"
  >
    <n-flex vertical>
      <n-alert type="info"> 当前需要额外在防火墙开放静态映射端口 </n-alert>
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
          <!-- <n-form-item-gi label="优先级" :span="2">
          <n-input-number v-model:value="rule.index" clearable />
        </n-form-item-gi> -->
          <n-form-item-gi label="启用" :span="2">
            <n-switch v-model:value="rule.enable">
              <template #checked> 启用 </template>
              <template #unchecked> 禁用 </template>
            </n-switch>
          </n-form-item-gi>

          <n-form-item-gi label="允许协议" :span="2">
            <n-flex justify="space-between" style="flex: 1">
              <n-flex>
                <n-checkbox
                  v-model:checked="allSelected"
                  :indeterminate="isIndeterminate"
                >
                  全选
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

          <!-- <n-form-item-gi :span="5" label="进入的 wan">
          <n-radio-group v-model:value="rule.wan_iface_name" name="filter">
            <n-radio-button
              v-for="opt in get_dns_filter_options()"
              :key="opt.value"
              :value="opt.value"
              :label="opt.label"
            />
          </n-radio-group>
        </n-form-item-gi> -->

          <n-form-item-gi
            path="wan_port"
            :span="1"
            label="开放端口 (不能与 NAT 映射端口重叠)"
          >
            <n-input-number
              style="flex: 1; padding-right: 10px"
              v-model:value="rule.wan_port"
              :min="1"
              :max="65535"
              placeholder="1-65535"
            />
          </n-form-item-gi>

          <n-form-item-gi path="lan_port" :span="1" label="内网目标端口">
            <n-input-number
              style="flex: 1"
              v-model:value="rule.lan_port"
              :min="1"
              :max="65535"
              placeholder="1-65535"
            />
          </n-form-item-gi>

          <n-form-item-gi :span="2" path="lan_ipv4" label="内网目标 IPv4">
            <n-input
              placeholder="如果开放的是路由的端口，那么就设置为 0.0.0.0 不映射留空即可"
              v-model:value="rule.lan_ipv4"
            />
          </n-form-item-gi>

          <n-form-item-gi :span="2" path="lan_ipv6" label="内网目标 IPv6">
            <n-input
              placeholder="如果开放的是路由的端口，那么就设置为 :: 不映射留空即可"
              v-model:value="rule.lan_ipv6"
            />
          </n-form-item-gi>

          <n-form-item-gi :span="2" label="备注">
            <n-input v-model:value="rule.remark" type="textarea" />
          </n-form-item-gi>
        </n-grid>
      </n-form>
    </n-flex>

    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">取消</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveRule"
          :disabled="!isModified"
        >
          保存
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
