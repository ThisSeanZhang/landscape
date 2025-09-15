<script setup lang="ts">
import { computed, ref } from "vue";
import FirewallRuleEditModal from "./FirewallRuleEditModal.vue";
import { FirewallRule } from "@/lib/mark";
import { delete_firewall_rule } from "@/api/firewall_rule";
const rule = defineModel<FirewallRule>("rule", { required: true });

const show_edit_modal = ref(false);

const emit = defineEmits(["refresh"]);

async function del() {
  if (rule.value.id !== null) {
    await delete_firewall_rule(rule.value.id);
    emit("refresh");
  }
}

const title_name = computed(() =>
  rule.value.remark == null || rule.value.remark === ""
    ? `无备注`
    : rule.value.remark
);
</script>
<template>
  <n-flex>
    <n-card size="small" style="flex: 1">
      <template #header>
        <StatusTitle
          :enable="rule.enable"
          :remark="`${rule.index}: ${title_name}`"
        ></StatusTitle>
      </template>
      <!-- {{ rule }} -->
      <n-descriptions bordered label-placement="top" :column="2">
        <n-descriptions-item label="匹配规则">
          <n-scrollbar style="max-height: 240px">
            <n-code
              :code="JSON.stringify(rule.items, null, 2)"
              language="json"
            ></n-code>
            <!-- {{ rule.items }} -->
          </n-scrollbar>
          <!-- {{ rule.items }} -->
        </n-descriptions-item>
      </n-descriptions>
      <template #header-extra>
        <n-flex>
          <n-button
            size="small"
            type="warning"
            secondary
            @click="show_edit_modal = true"
          >
            编辑
          </n-button>

          <n-popconfirm @positive-click="del()">
            <template #trigger>
              <n-button size="small" type="error" secondary @click="">
                删除
              </n-button>
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
