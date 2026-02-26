<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import DnsRuleEditModal from "@/components/dns/DnsRuleEditModal.vue";
import { DnsRule } from "@/lib/dns";
import { delDnsRules } from "@landscape-router/types/api/dns-rules/dns-rules";
import { CheckmarkOutline } from "@vicons/carbon";
import FlowMarkExhibit from "@/components/flow/FlowMarkExhibit.vue";
const rule = defineModel<DnsRule>("rule", { required: true });
const { t } = useI18n();

const show_edit_modal = ref(false);

const emit = defineEmits(["refresh"]);

async function del() {
  if (rule.value.id) {
    await delDnsRules(rule.value.id);
    emit("refresh");
  }
}

const title_name = computed(() =>
  rule.value.name == null || rule.value.name === ""
    ? t("common.no_remark")
    : rule.value.name,
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
        <n-descriptions-item :label="t('dns_editor.rule_card.traffic_action')">
          <FlowMarkExhibit
            :mark="rule.mark"
            :flow_id="rule.flow_id"
          ></FlowMarkExhibit>
          <!-- {{ rule.mark }} -->
        </n-descriptions-item>
        <n-descriptions-item :label="t('dns_editor.rule_card.upstream_config')">
          <UpstreamExhibit :rule_id="rule.upstream_id"></UpstreamExhibit>
          <!-- {{ rule.resolve_mode }} -->
        </n-descriptions-item>
        <n-descriptions-item :label="t('dns_editor.rule_card.match_rules')" span="2">
          <n-scrollbar v-if="rule.source.length > 0" style="max-height: 120px">
            <n-flex>
              <RuleSourceExhibit v-for="item in rule.source" :source="item">
              </RuleSourceExhibit>
            </n-flex>
          </n-scrollbar>
          <n-empty v-else :description="t('dns_editor.rule_card.no_match_rules')">
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
    <DnsRuleEditModal
      @refresh="emit('refresh')"
      :flow_id="rule.flow_id"
      :rule_id="rule.id"
      v-model:show="show_edit_modal"
    ></DnsRuleEditModal>
  </n-flex>
</template>
