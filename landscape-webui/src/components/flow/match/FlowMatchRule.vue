<script setup lang="ts">
import { FlowEntryRule } from "@/rust_bindings/common/flow";
import { useFrontEndStore } from "@/stores/front_end_config";
import { ChangeCatalog } from "@vicons/carbon";
import { formatMacAddress } from "@/lib/util";

const frontEndStore = useFrontEndStore();
const match_rules = defineModel<FlowEntryRule[]>("match_rules", {
  required: true,
});

function onCreate(): FlowEntryRule {
  return {
    qos: null,
    mode: {
      t: "ip",
      ip: "",
      prefix_len: 32,
    },
  };
}

function change_mode(value: FlowEntryRule, index: number) {
  let temp_rule = match_rules.value[index];
  if (value.mode.t == "ip") {
    match_rules.value[index] = {
      qos: temp_rule.qos,
      mode: {
        t: "mac",
        mac_addr: "",
      },
    };
  } else {
    match_rules.value[index] = {
      qos: temp_rule.qos,
      mode: {
        t: "ip",
        ip: "",
        prefix_len: 32,
      },
    };
  }
}
</script>

<template>
  <n-dynamic-input v-model:value="match_rules" :on-create="onCreate">
    <template #create-button-default> 增加一条入口匹配规则 </template>
    <template #default="{ value, index }">
      <n-flex style="flex: 1" :wrap="false">
        <n-button @click="change_mode(value, index)">
          <n-icon>
            <ChangeCatalog />
          </n-icon>
        </n-button>
        <!-- <n-input-number
          v-model:value="value.qos"
          min="0"
          max="255"
          :style="{ width: '33%' }"
          placeholder="QoS"
          :show-button="false"
        /> -->

        <n-input
          v-if="value.mode.t == 'mac'"
          :type="frontEndStore.presentation_mode ? 'password' : 'text'"
          :value="value.mode.mac_addr"
          @update:value="
            (v: string) => (value.mode.mac_addr = formatMacAddress(v))
          "
          placeholder="请输入 MAC 地址，优先级比 IP 低"
        />
        <n-input-group v-else>
          <n-input
            :type="frontEndStore.presentation_mode ? 'password' : 'text'"
            v-model:value="value.mode.ip"
            placeholder="IP 地址"
          />
          <n-input-group-label>/</n-input-group-label>
          <n-input-number
            v-model:value="value.mode.prefix_len"
            :style="{ width: '60px' }"
            placeholder="前缀长度"
            :show-button="false"
          />
          <!-- <n-input-number
          v-model:value="value.vlan_id"
          :style="{ width: '33%' }"
          placeholder="VLAN ID"
          :show-button="false"
        /> -->
        </n-input-group>
      </n-flex>
    </template>
  </n-dynamic-input>
</template>
