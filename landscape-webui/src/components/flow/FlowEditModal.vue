<script setup lang="ts">
import { get_flow_rule, push_flow_rules } from "@/api/flow";
import { useMessage } from "naive-ui";
import { computed } from "vue";
import { ref } from "vue";
import FlowMatchRule from "./match/FlowMatchRule.vue";
import { flow_config_default, FlowTargetTypes } from "@/lib/default_value";
import { FlowConfig, FlowTarget } from "@/rust_bindings/common/flow";
import { useFrontEndStore } from "@/stores/front_end_config";
interface Props {
  rule_id?: string;
}

const props = defineProps<Props>();

const frontEndStore = useFrontEndStore();

const message = useMessage();

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const rule_json = ref("");
const rule = ref<FlowConfig>();

const commit_spin = ref(false);
const isModified = computed(() => {
  return JSON.stringify(rule.value) !== rule_json.value;
});

async function enter() {
  if (props.rule_id) {
    rule.value = await get_flow_rule(props.rule_id);
  } else {
    rule.value = flow_config_default();
  }

  rule_json.value = JSON.stringify(rule.value);
}

function exit() {
  rule.value = flow_config_default();
  rule_json.value = JSON.stringify(rule.value);
}

async function saveRule() {
  if (!rule.value) {
    return;
  }

  if (rule.value.flow_id == -1) {
    message.warning("**ID** 值不能为 -1, 且不能重复, 否则将会覆盖规则");
    return;
  }
  try {
    commit_spin.value = true;
    await push_flow_rules(rule.value);
    console.log("submit success");
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
    @after-leave="exit"
    :bordered="false"
  >
    <!-- {{ rule }} -->
    <n-form v-if="rule" style="flex: 1" ref="formRef" :model="rule" :cols="5">
      <n-grid :cols="5">
        <n-form-item-gi label="流 ID 标识" :span="2">
          <n-input-number
            :min="1"
            :max="255"
            v-model:value="rule.flow_id"
            clearable
          />
        </n-form-item-gi>
        <n-form-item-gi label="启用" :offset="1" :span="1">
          <n-switch v-model:value="rule.enable">
            <template #checked> 启用 </template>
            <template #unchecked> 禁用 </template>
          </n-switch>
        </n-form-item-gi>

        <n-form-item-gi :span="5" label="备注">
          <n-input
            :type="frontEndStore.presentation_mode ? 'password' : 'text'"
            v-model:value="rule.remark"
          />
        </n-form-item-gi>
      </n-grid>
      <n-form-item label="分流入口匹配规则">
        <FlowMatchRule v-model:match_rules="rule.flow_match_rules">
        </FlowMatchRule>
      </n-form-item>
      <n-form-item label="分流出口规则 ( 当前仅支持一个出口 )">
        <FlowTargetRule v-model:target_rules="rule.flow_targets">
        </FlowTargetRule>
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
