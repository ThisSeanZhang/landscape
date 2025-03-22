<script setup lang="ts">
import { computed } from "vue";
import { ref } from "vue";
import { useMessage } from "naive-ui";
import { ChangeCatalog } from "@vicons/carbon";

import { post_firewall_rules } from "@/api/mark";
import PacketMark from "@/components/mark/PacketMark.vue";
import NewIpEdit from "@/components/NewIpEdit.vue";
import {
  protocol_options,
  FirewallRuleConfig,
  FirewallRuleItem,
} from "@/lib/mark";

const message = useMessage();

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const origin_rule = defineModel<FirewallRuleConfig>("rule", {
  default: new FirewallRuleConfig(),
});
const rule = ref<FirewallRuleConfig>(new FirewallRuleConfig(origin_rule.value));

const commit_spin = ref(false);
const isModified = computed(() => {
  return JSON.stringify(rule.value) !== JSON.stringify(origin_rule.value);
});

function onCreate(): FirewallRuleItem {
  return new FirewallRuleItem({});
}

async function saveRule() {
  if (rule.value.index == -1) {
    message.warning("**优先级** 值不能为 -1");
    return;
  }
  try {
    commit_spin.value = true;
    await post_firewall_rules(rule.value);
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
</script>

<template>
  <n-modal
    v-model:show="show"
    style="width: 700px"
    class="custom-card"
    preset="card"
    title="防火墙规则编辑"
    :bordered="false"
  >
    <!-- {{ isModified }} -->
    <n-form style="flex: 1" ref="formRef" :model="rule" :cols="5">
      <n-grid :cols="5">
        <n-form-item-gi
          label="优先级 (与已有规则 index 重复将会覆盖)"
          :span="2"
        >
          <n-input-number v-model:value="rule.index" clearable />
        </n-form-item-gi>
        <n-form-item-gi label="启用" :offset="1" :span="1">
          <n-switch v-model:value="rule.enable">
            <template #checked> 启用 </template>
            <template #unchecked> 禁用 </template>
          </n-switch>
        </n-form-item-gi>

        <!-- <n-form-item-gi :span="5" label="流量标记">
          <PacketMark v-model:mark="rule.mark"></PacketMark>
        </n-form-item-gi> -->
      </n-grid>
      <n-form-item label="备注">
        <n-input v-model:value="rule.remark" type="text" />
      </n-form-item>
      <n-form-item label="匹配规则">
        <n-dynamic-input v-model:value="rule.items" :on-create="onCreate">
          <template #create-button-default> 增加一条 Lan 规则 </template>
          <template #default="{ value, index }">
            <n-input-group>
              <n-select
                style="width: 200px"
                v-model:value="value.ip_protocol"
                :options="protocol_options()"
              />
              <n-input-number
                :show-button="false"
                placeholder="端口"
                v-model:value="value.local_port"
              />
              <n-input
                v-model:value="value.address"
                placeholder="geo key"
                type="text"
              />
              <n-input-group-label>/</n-input-group-label>
              <n-input-number
                :show-button="false"
                placeholder="掩码长度"
                v-model:value="value.ip_prefixlen"
              />
            </n-input-group>
          </template>
        </n-dynamic-input>
      </n-form-item>
    </n-form>
    <template #footer>
      <n-flex justify="space-between">
        <n-button>取消</n-button>
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
