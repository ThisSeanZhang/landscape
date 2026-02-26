<script setup lang="ts">
import { ref } from "vue";
import { delete_dns_redirect } from "@/api/dns_rule/redirect";
import type { DNSRedirectRule } from "@landscape-router/types/api/schemas";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useI18n } from "vue-i18n";

const frontEndStore = useFrontEndStore();
const { t } = useI18n();
type Props = {
  rule: DNSRedirectRule;
};

const props = defineProps<Props>();
const emit = defineEmits(["refresh"]);

const show_edit_modal = ref(false);
async function del() {
  if (props.rule.id) {
    await delete_dns_redirect(props.rule.id);
    emit("refresh");
  }
}
</script>

<template>
  <n-card size="small">
    <template #header>
      <StatusTitle :enable="rule.enable" :remark="rule.remark"></StatusTitle>
    </template>

    <n-descriptions
      label-style="width: 81px"
      bordered
      label-placement="left"
      :column="1"
      size="small"
    >
      <n-descriptions-item label="应用于">
        <n-flex v-if="rule.apply_flows.length > 0">
          <n-tag v-for="value in rule.apply_flows" :bordered="false">
            {{ value === 0 ? "默认流" : value }}
          </n-tag>
        </n-flex>
        <n-flex v-else>
          <span style="min-height: 28px">全部 Flow </span>
        </n-flex>
      </n-descriptions-item>

      <n-descriptions-item label="回应信息">
        <n-flex v-if="rule.result_info.length > 0">
          <n-tag v-for="value in rule.result_info" :bordered="false">
            {{ frontEndStore.MASK_INFO(value) }}
          </n-tag>
        </n-flex>
      </n-descriptions-item>

      <n-descriptions-item :label="t('dns_editor.rule_card.match_rules')">
        <n-scrollbar style="height: 90px">
          <n-flex>
            <RuleSourceExhibit v-for="item in rule.match_rules" :source="item">
            </RuleSourceExhibit>
          </n-flex>
        </n-scrollbar>
        <!-- {{ rule.match_rules }} -->
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
          {{ t("common.edit") }}
        </n-button>

        <n-popconfirm @positive-click="del()">
          <template #trigger>
            <n-button size="small" type="error" secondary @click="">
              {{ t("common.delete") }}
            </n-button>
          </template>
          {{ t("common.confirm_delete") }}
        </n-popconfirm>
      </n-flex>
    </template>
  </n-card>
  <DnsRedirectEditModal
    @refresh="emit('refresh')"
    :rule_id="rule.id"
    v-model:show="show_edit_modal"
  >
  </DnsRedirectEditModal>
</template>
