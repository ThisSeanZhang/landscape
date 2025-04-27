<script setup lang="ts">
import { computed } from "vue";
import { ref } from "vue";
import { useMessage } from "naive-ui";
import { ChangeCatalog } from "@vicons/carbon";

import {
  post_wan_ip_rules,
  get_wan_ip_rule,
  update_wan_ip_rules,
} from "@/api/flow/wanip";
import FlowDnsMark from "@/components/flow/FlowDnsMark.vue";
import NewIpEdit from "@/components/NewIpEdit.vue";
import { WanIPRuleSource, WanIPRuleConfig } from "@/rust_bindings/flow";

import { new_wan_rules, WanIPRuleConfigClass } from "@/lib/mark";

interface Props {
  flow_id: number;
  id?: string;
}

const props = defineProps<Props>();

const message = useMessage();
const emit = defineEmits(["refresh"]);
const show = defineModel<boolean>("show", { required: true });

async function enter() {
  if (props.id) {
    rule.value = await get_wan_ip_rule(props.flow_id, props.id);
  } else {
    rule.value = new WanIPRuleConfigClass({
      flow_id: props.flow_id,
    });
  }
  origin_rule_json.value = JSON.stringify(rule.value);
}

const origin_rule_json = ref("");
// const origin_rule = defineModel<WanIPRuleConfig>("rule", {
//   default: new WanIPRuleConfigClass({
//     flow_id: props.flow_id,
//   }),
// });
const rule = ref<WanIPRuleConfig>();

const commit_spin = ref(false);
const isModified = computed(() => {
  return origin_rule_json.value !== JSON.stringify(rule.value);
});

function onCreate(): WanIPRuleSource {
  return new_wan_rules({ t: "config", ip: "0.0.0.0", prefix: 32 });
}

function changeCurrentRuleType(value: WanIPRuleSource, index: number) {
  if (rule.value) {
    if (value.t == "config") {
      rule.value.source[index] = { t: "geokey", country_code: "" };
    } else {
      rule.value.source[index] = new_wan_rules({
        t: "config",
        ip: "0.0.0.0",
        prefix: 32,
      });
    }
  }
}

async function saveRule() {
  if (rule.value) {
    if (rule.value.index == -1) {
      message.warning("**优先级** 值不能为 -1, 且不能重复, 否则将会覆盖规则");
      return;
    }
    try {
      commit_spin.value = true;
      if (props.id) {
        await update_wan_ip_rules(props.flow_id, props.id, rule.value);
      } else {
        await post_wan_ip_rules(props.flow_id, rule.value);
      }
      console.log("submit success");
      show.value = false;
    } catch (e: any) {
      message.error(`${e.response.data}`);
    } finally {
      commit_spin.value = false;
    }
    emit("refresh");
  }
}
</script>

<template>
  <n-modal
    v-model:show="show"
    style="width: 700px"
    class="custom-card"
    preset="card"
    title="规则编辑"
    @after-enter="enter"
    :bordered="false"
  >
    <!-- {{ isModified }} -->
    <n-form v-if="rule" style="flex: 1" ref="formRef" :model="rule" :cols="5">
      <n-grid :cols="5">
        <n-form-item-gi label="优先级" :span="2">
          <n-input-number v-model:value="rule.index" clearable />
        </n-form-item-gi>
        <n-form-item-gi label="启用" :offset="1" :span="1">
          <n-switch v-model:value="rule.enable">
            <template #checked> 启用 </template>
            <template #unchecked> 禁用 </template>
          </n-switch>
        </n-form-item-gi>
        <n-form-item-gi label="覆盖 DNS 配置" :span="1">
          <n-switch v-model:value="rule.override_dns">
            <template #checked> 覆盖 </template>
            <template #unchecked> 不覆盖 </template>
          </n-switch>
        </n-form-item-gi>

        <n-form-item-gi :span="5" label="流量标记">
          <FlowDnsMark v-model:mark="rule.mark"></FlowDnsMark>
        </n-form-item-gi>
      </n-grid>
      <n-form-item label="备注">
        <n-input v-model:value="rule.remark" type="text" />
      </n-form-item>
      <n-form-item label="匹配的 IP">
        <n-dynamic-input v-model:value="rule.source" :on-create="onCreate">
          <template #create-button-default> 增加一条 Lan 规则 </template>
          <template #default="{ value, index }">
            <n-flex style="flex: 1" :wrap="false">
              <n-button @click="changeCurrentRuleType(value, index)">
                <n-icon>
                  <ChangeCatalog />
                </n-icon>
              </n-button>
              <n-input
                v-if="value.t === 'geokey'"
                v-model:value="value.key"
                placeholder="geo key"
                type="text"
              />
              <n-flex v-else style="flex: 1">
                <NewIpEdit
                  v-model:ip="value.ip"
                  v-model:mask="value.prefix"
                ></NewIpEdit>
              </n-flex>
            </n-flex>
          </template>
        </n-dynamic-input>
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
