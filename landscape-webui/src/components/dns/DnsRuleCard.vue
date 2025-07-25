<script setup lang="ts">
import { ref } from "vue";
import DnsRuleEditModal from "@/components/dns/DnsRuleEditModal.vue";
import { DnsRule } from "@/lib/dns";
import { delete_dns_rule } from "@/api/dns_rule";
const rule = defineModel<DnsRule>("rule", { required: true });

const show_edit_modal = ref(false);

const emit = defineEmits(["refresh"]);

async function del() {
  if (rule.value.id !== null) {
    await delete_dns_rule(rule.value.id);
    emit("refresh");
  }
}
</script>
<template>
  <n-flex>
    <n-card :title="`优先级:${rule.index}`" size="small">
      <!-- {{ rule }} -->
      <n-descriptions bordered label-placement="top" :column="3">
        <n-descriptions-item label="名称">
          {{ rule.name }}
        </n-descriptions-item>
        <n-descriptions-item label="启用">
          <span :style="{ color: rule.enable ? 'var(--success-color)' : '' }">
            {{ rule.enable }}
          </span>
        </n-descriptions-item>
        <n-descriptions-item label="流量标记">
          {{ rule.mark }}
        </n-descriptions-item>
        <n-descriptions-item label="DNS 处理方式" :span="2">
          {{ rule.resolve_mode }}
        </n-descriptions-item>
        <n-descriptions-item label="匹配规则">
          {{ rule.source }}
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
    <DnsRuleEditModal
      @refresh="emit('refresh')"
      :flow_id="rule.flow_id"
      :rule_id="rule.id"
      v-model:show="show_edit_modal"
    ></DnsRuleEditModal>
  </n-flex>
</template>