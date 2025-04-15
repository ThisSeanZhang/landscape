<script setup lang="ts">
import { push_flow_rules } from "@/api/flow";
import { useMessage } from "naive-ui";

import { ChangeCatalog } from "@vicons/carbon";
import { computed, onMounted, toRaw } from "vue";
import { ref } from "vue";
import FlowMatchRule from "./match/FlowMatchRule.vue";
import {
  flow_config_default,
  FlowTargetTypes,
  flow_target_options,
} from "@/lib/default_value";
import { FlowConfig, FlowTarget } from "@/rust_bindings/flow";

const message = useMessage();

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const origin_rule = defineModel<FlowConfig>("rule", {
  default: flow_config_default(),
});
const rule = ref<FlowConfig>(structuredClone(toRaw(origin_rule.value)));

const commit_spin = ref(false);
const isModified = computed(() => {
  return JSON.stringify(rule.value) !== JSON.stringify(origin_rule.value);
});

function enter() {
  rule.value = structuredClone(toRaw(origin_rule.value));
}

async function saveRule() {
  if (rule.value.flow_id == -1) {
    message.warning("**ID** 值不能为 -1, 且不能重复, 否则将会覆盖规则");
    return;
  }
  try {
    commit_spin.value = true;
    await push_flow_rules(rule.value);
    console.log("submit success");
    origin_rule.value = rule.value;
    show.value = false;
  } catch (e: any) {
    message.error(`${e.response.data}`);
  } finally {
    commit_spin.value = false;
  }
  emit("refresh");
}

function create_target(): FlowTarget {
  return { t: FlowTargetTypes.INTERFACE, name: "" };
}

function switch_target() {}
</script>

<template>
  <n-modal
    v-model:show="show"
    style="width: 600px"
    class="custom-card"
    preset="card"
    title="分流规则编辑"
    @after-enter="enter"
    :bordered="false"
  >
    <!-- {{ rule }} -->
    <n-form style="flex: 1" ref="formRef" :model="rule" :cols="5">
      <n-grid :cols="5">
        <n-form-item-gi label="流 ID 标识" :span="2">
          <n-input-number v-model:value="rule.flow_id" clearable />
        </n-form-item-gi>
        <n-form-item-gi label="启用" :offset="1" :span="1">
          <n-switch v-model:value="rule.enable">
            <template #checked> 启用 </template>
            <template #unchecked> 禁用 </template>
          </n-switch>
        </n-form-item-gi>

        <n-form-item-gi :span="2" label="备注">
          <n-input v-model:value="rule.remark" type="text" />
        </n-form-item-gi>
        <!-- <n-form-item-gi :span="5" label="分流目标网卡">
          <n-dynamic-input
            v-model:value="rule.packet_handle_iface_name"
            :on-create="create_target"
            max="1"
          >
            <template #create-button-default> 增加一个发送目标 </template>
            <template #default="{ value, index }">
              <n-input-group>
                <n-select
                  v-model:value="value.t"
                  :style="{ width: '33%' }"
                  :options="flow_target_options()"
                />
                <n-input
                  v-if="value.t === FlowTargetTypes.INTERFACE"
                  v-model:value="value.name"
                  :style="{ width: '66%' }"
                  placeholder="网卡名称"
                />
                <n-input
                  v-else-if="value.t === FlowTargetTypes.NETNS"
                  v-model:value="value.container_name"
                  :style="{ width: '66%' }"
                  placeholder="容器名称"
                />
              </n-input-group>
            </template>
          </n-dynamic-input>
        </n-form-item-gi> -->
      </n-grid>
      <n-form-item label="流匹配规则">
        <FlowMatchRule v-model:match_rules="rule.flow_match_rules">
        </FlowMatchRule>
      </n-form-item>
    </n-form>
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
