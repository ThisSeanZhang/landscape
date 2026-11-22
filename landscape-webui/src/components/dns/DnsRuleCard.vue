<script setup lang="ts">
import type { DNSRuleConfig } from "@landscape-router/types/api/schemas";
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import RoutingRuleCard from "@/components/flow/RoutingRuleCard.vue";
import { DnsServices } from "@vicons/carbon";
import DnsRuleEditModal from "@/components/dns/DnsRuleEditModal.vue";
import { delDnsRules } from "@landscape-router/types/api/dns-rules/dns-rules";
import FlowMarkExhibit from "@/components/flow/FlowMarkExhibit.vue";

const { rule } = defineProps<{ rule: DNSRuleConfig }>();
const { t } = useI18n();
const emit = defineEmits<{ refresh: [] }>();
const showEditor = ref(false);
const filterDisplay = {
  unfilter: { label: "dns.rule_edit.filter_unfilter", tone: "default" },
  only_ipv4: { label: "dns.rule_edit.filter_ipv4", tone: "info" },
  only_ipv6: { label: "dns.rule_edit.filter_ipv6", tone: "success" },
} as const;

const filter = computed(() => filterDisplay[rule.filter ?? "unfilter"]);

async function deleteRule() {
  if (rule.id) {
    await delDnsRules(rule.id);
    emit("refresh");
  }
}
</script>

<template>
  <RoutingRuleCard
    :title="rule.name?.trim() || t('common.no_remark')"
    :enabled="rule.enable"
    :priority="rule.index"
    :sources="rule.source"
    :delete-rule="deleteRule"
    @edit="showEditor = true"
  >
    <template #summary>
      <div class="upstream">
        <n-icon aria-hidden="true"><DnsServices /></n-icon>
        <span>{{ t("dns.rule_card.upstream_config") }}</span>
        <strong><UpstreamExhibit :rule_id="rule.upstream_id" /></strong>
      </div>
    </template>

    <dl class="rule-facts">
      <div>
        <dt>{{ t("flow.rule_card.traffic_routing") }}</dt>
        <dd><FlowMarkExhibit :mark="rule.mark" :flow_id="rule.flow_id" /></dd>
      </div>
      <div>
        <dt>{{ t("dns.rule_card.answer_filter") }}</dt>
        <dd>
          <n-tag size="small" :bordered="false" :type="filter.tone">
            {{ t(filter.label) }}
          </n-tag>
        </dd>
      </div>
    </dl>

    <template #source="{ source }">
      <RuleSourceExhibit :source="source" />
    </template>
    <template #empty>
      <n-text>{{ t("dns.rule_card.no_match_rules") }}</n-text>
    </template>
  </RoutingRuleCard>
  <DnsRuleEditModal
    v-model:show="showEditor"
    :flow_id="rule.flow_id"
    :rule_id="rule.id"
    @refresh="emit('refresh')"
  />
</template>

<style scoped>
.upstream {
  min-width: 0;
  color: var(--muted);
  font-size: 12px;
}
.upstream .n-icon {
  vertical-align: -0.12em;
  margin-inline-end: 4px;
  color: var(--accent);
}
.upstream strong {
  margin-inline-start: 4px;
  font-weight: 500;
}
.rule-facts {
  display: grid;
  grid-template-columns: minmax(0, 3fr) minmax(0, 2fr);
  margin: 12px;
}
.rule-facts > div + div {
  padding-inline-start: 12px;
  border-inline-start: 1px solid var(--n-border-color);
}
.rule-facts dt {
  margin: 0 0 4px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 500;
}
.rule-facts dd {
  display: flex;
  align-items: flex-start;
  margin: 0;
}
.rule-facts dd :deep(.n-tag) {
  height: auto;
  min-height: var(--n-height);
  max-width: 100%;
  line-height: 1.35;
  white-space: normal;
}
</style>
