<script setup lang="ts">
import { computed, ref } from "vue";
import WanRuleEditModal from "./WanRuleEditModal.vue";
import { WanIpRuleConfig } from "@/rust_bindings/common/flow";
import { delete_dst_ip_rules_rule } from "@/api/dst_ip_rule";
import { Warning } from "@vicons/carbon";
const rule = defineModel<WanIpRuleConfig>("rule", { required: true });

const show_edit_modal = ref(false);

const emit = defineEmits(["refresh"]);

async function del() {
  if (rule.value.id !== null) {
    await delete_dst_ip_rules_rule(rule.value.id);
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
    <n-card size="small">
      <template #header>
        <StatusTitle
          :enable="rule.enable"
          :remark="`${rule.index}: ${title_name}`"
        ></StatusTitle>
      </template>
      <!-- {{ rule }} -->
      <n-descriptions bordered label-placement="top" :column="1">
        <n-descriptions-item label="流量标记">
          <MarkExhibit :mark="rule.mark" :flow_id="rule.flow_id"></MarkExhibit>
        </n-descriptions-item>
        <n-descriptions-item label="匹配规则">
          <n-scrollbar v-if="rule.source.length > 0" style="max-height: 120px">
            {{ rule.source }}
          </n-scrollbar>
          <n-empty v-else description="无匹配规则, 没有任何作用">
            <template #icon>
              <n-icon>
                <Warning />
              </n-icon>
            </template>
          </n-empty>
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
    <WanRuleEditModal
      :flow_id="rule.flow_id"
      :id="rule.id"
      @refresh="emit('refresh')"
      :rule="rule"
      v-model:show="show_edit_modal"
    ></WanRuleEditModal>
  </n-flex>
</template>
