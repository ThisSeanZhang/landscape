<script setup lang="ts">
import { computed, reactive } from "vue";
import type { FlowEntryRule } from "landscape-types/api/schemas";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";
import { ChangeCatalog } from "@vicons/carbon";
import { formatMacAddress } from "@/lib/util";

const frontEndStore = useFrontEndStore();
const enrolledDeviceStore = useEnrolledDeviceStore();
const match_rules = defineModel<FlowEntryRule[]>("match_rules", {
  required: true,
});

type InputMode = "select" | "mac" | "ip";
const inputModes = reactive(new Map<number, InputMode>());

function getInputMode(index: number): InputMode {
  return (
    inputModes.get(index) ??
    (match_rules.value[index]?.mode.t === "ip" ? "ip" : "select")
  );
}

const deviceOptions = computed(() =>
  enrolledDeviceStore.bindings.map((d) => ({
    label: d.name,
    value: d.mac,
  })),
);

function onCreate(): FlowEntryRule {
  const index = match_rules.value.length;
  inputModes.set(index, "select");
  return {
    qos: null,
    mode: {
      t: "mac",
      mac_addr: "",
    },
  };
}

function change_mode(value: FlowEntryRule, index: number) {
  const current = getInputMode(index);
  const temp_rule = match_rules.value[index];
  if (current === "select") {
    inputModes.set(index, "mac");
  } else if (current === "mac") {
    inputModes.set(index, "ip");
    match_rules.value[index] = {
      qos: temp_rule.qos,
      mode: {
        t: "ip",
        ip: "",
        prefix_len: 32,
      },
    };
  } else {
    inputModes.set(index, "select");
    match_rules.value[index] = {
      qos: temp_rule.qos,
      mode: {
        t: "mac",
        mac_addr: "",
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

        <n-select
          v-if="getInputMode(index) === 'select'"
          :options="deviceOptions"
          :value="value.mode.mac_addr || null"
          @update:value="(v: string) => (value.mode.mac_addr = v)"
          placeholder="选择已登记设备"
          clearable
          filterable
          :style="{ minWidth: '140px', flex: 1 }"
        />
        <n-input
          v-else-if="getInputMode(index) === 'mac'"
          :type="frontEndStore.presentation_mode ? 'password' : 'text'"
          :value="value.mode.mac_addr"
          @update:value="
            (v: string) => (value.mode.mac_addr = formatMacAddress(v))
          "
          placeholder="手动输入 MAC 地址"
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
        </n-input-group>
      </n-flex>
    </template>
  </n-dynamic-input>
</template>
