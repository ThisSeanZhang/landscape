<script setup lang="ts">
import { PacketMatchMark } from "@/rust_bindings/common/flow";
import { useFrontEndStore } from "@/stores/front_end_config";

const frontEndStore = useFrontEndStore();
const match_rules = defineModel<PacketMatchMark[]>("match_rules", {
  required: true,
});

function onCreate(): PacketMatchMark {
  return {
    ip: "",
    vlan_id: null,
    qos: null,
    prefix_len: 32,
  };
}
</script>

<template>
  <n-dynamic-input v-model:value="match_rules" :on-create="onCreate">
    <template #create-button-default> 增加一条入口匹配规则 </template>
    <template #default="{ value, index }">
      <n-input-group>
        <n-input-number
          v-model:value="value.qos"
          min="0"
          max="255"
          :style="{ width: '33%' }"
          placeholder="QoS"
          :show-button="false"
        />
        <n-input
          :type="frontEndStore.presentation_mode ? 'password' : 'text'"
          v-model:value="value.ip"
          :style="{ width: '66%' }"
          placeholder="IP 地址"
        />
        <n-input-group-label>/</n-input-group-label>
        <n-input-number
          v-model:value="value.prefix_len"
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
    </template>
  </n-dynamic-input>
</template>
