<script setup lang="ts">
import { ref } from "vue";
import FirewallRuleEditModal from "./FirewallRuleEditModal.vue";
import { del_firewall_rules } from "@/api/mark";
import { FirewallRuleConfig } from "@/lib/mark";
const rule = defineModel<FirewallRuleConfig>("rule", { required: true });

const show_edit_modal = ref(false);

const emit = defineEmits(["refresh"]);

async function del() {
  await del_firewall_rules(rule.value.index);
  emit("refresh");
}
</script>
<template>
  <n-flex>
    <n-card :title="`优先级:${rule.index}`" size="small">
      <!-- {{ rule }} -->
      <n-descriptions bordered label-placement="top" :column="2">
        <n-descriptions-item label="启用">
          {{ rule.enable }}
        </n-descriptions-item>
        <!-- <n-descriptions-item label="流量标记">
          {{ rule.mark }}
        </n-descriptions-item> -->
        <n-descriptions-item label="备注">
          {{ rule.remark }}
        </n-descriptions-item>
        <n-descriptions-item label="匹配规则">
          {{ rule.items }}
        </n-descriptions-item>
      </n-descriptions>
      <template #header-extra>
        <n-flex>
          <n-button type="warning" secondary @click="show_edit_modal = true">
            编辑
          </n-button>

          <n-popconfirm @positive-click="del()">
            <template #trigger>
              <n-button type="error" secondary @click=""> 删除 </n-button>
            </template>
            确定删除吗
          </n-popconfirm>
        </n-flex>
      </template>
    </n-card>
    <FirewallRuleEditModal
      @refresh="emit('refresh')"
      :rule="rule"
      v-model:show="show_edit_modal"
    ></FirewallRuleEditModal>
  </n-flex>
</template>
