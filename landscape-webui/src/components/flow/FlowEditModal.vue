<script setup lang="ts">
import {
  getFlowRule,
  addFlowRule,
} from "landscape-types/api/flow-rules/flow-rules";
import { useMessage } from "naive-ui";
import { computed } from "vue";
import { ref } from "vue";
import FlowMatchRule from "./match/FlowMatchRule.vue";
import { flow_config_default, FlowTargetTypes } from "@/lib/default_value";
import type {
  FlowConfig,
  FlowEntryRule,
  FlowTarget,
} from "landscape-types/api/schemas";
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
    rule.value = await getFlowRule(props.rule_id);
  } else {
    rule.value = flow_config_default();
  }

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
    } else {
      key = `ip:${rule.mode.ip}/${rule.mode.prefix_len}`;
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

  if (rule.value.flow_id == -1) {
    message.warning("**ID** 值不能为 -1, 且不能重复, 否则将会覆盖规则");
    return;
  }

  const dup = findDuplicateEntryRules(rule.value.flow_match_rules);
  if (dup) {
    message.warning(`入口匹配规则存在重复项: ${dup}`);
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
      <n-form-item>
        <template #label>
          <Notice
            >分流入口匹配规则
            <template #msg>
              符合规则的客户端将会使用这个流<br />
              注意优先级 IP > Mac <br />
              注意不同 Flow 的规则是否重叠
            </template>
          </Notice>
        </template>
        <FlowMatchRule v-model:match_rules="rule.flow_match_rules">
        </FlowMatchRule>
      </n-form-item>
      <n-form-item label="">
        <template #label>
          <Notice>
            分流出口规则 ( 当前仅支持一个出口 )
            <template #msg>
              符合规则的客户端将会默认使用这个出口进行发送流量<br />
              除非 `DNS 规则` 或者 `目标 IP` 将流量重定向到别的流
            </template>
          </Notice>
        </template>

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
