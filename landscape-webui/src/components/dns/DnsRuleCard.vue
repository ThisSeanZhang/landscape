<script setup lang="ts">
import { computed, ref } from "vue";
import DnsRuleEditModal from "@/components/dns/DnsRuleEditModal.vue";
import { DnsRule } from "@/lib/dns";
import { delete_dns_rule } from "@/api/dns_rule";
import { CheckmarkOutline } from "@vicons/carbon";
const rule = defineModel<DnsRule>("rule", { required: true });

const show_edit_modal = ref(false);

const emit = defineEmits(["refresh"]);

async function del() {
  if (rule.value.id) {
    await delete_dns_rule(rule.value.id);
    emit("refresh");
  }
}

const title_name = computed(() =>
  rule.value.name == null || rule.value.name === "" ? `无备注` : rule.value.name
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
      <n-descriptions bordered label-placement="top" :column="2">
        <!-- <n-descriptions-item label="优先级">
          {{ rule.index }}
        </n-descriptions-item> -->
        <n-descriptions-item label="流量动作">
          <MarkExhibit :mark="rule.mark" :flow_id="rule.flow_id"></MarkExhibit>
          <!-- {{ rule.mark }} -->
        </n-descriptions-item>
        <n-descriptions-item label="DNS 上游配置">
          <UpstreamExhibit  :rule_id="rule.upstream_id"></UpstreamExhibit>
          <!-- {{ rule.resolve_mode }} -->
        </n-descriptions-item>
        <n-descriptions-item label="匹配规则" span="2">
          <n-scrollbar v-if="rule.source.length > 0" style="max-height: 120px">
            <n-flex>
              <RuleSourceExhibit v-for="rule in rule.source" :source="rule">
              </RuleSourceExhibit>
            </n-flex>
          </n-scrollbar>
          <n-empty v-else description="无匹配规则, 将会匹配所有域名">
            <template #icon>
              <n-icon>
                <CheckmarkOutline />
              </n-icon>
            </template>
          </n-empty>
          <!-- {{ rule.source }} -->
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
    <DnsRuleEditModal
      @refresh="emit('refresh')"
      :flow_id="rule.flow_id"
      :rule_id="rule.id"
      v-model:show="show_edit_modal"
    ></DnsRuleEditModal>
  </n-flex>
</template>
