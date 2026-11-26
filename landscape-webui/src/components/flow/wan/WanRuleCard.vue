<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Warning } from "@vicons/carbon";
import type { WanIpRuleConfig } from "@landscape-router/types/api/schemas";
import { delete_dst_ip_rules_rule } from "@/api/dst_ip_rule";
import { useFrontEndStore } from "@/stores/front_end_config";
import FlowMarkExhibit from "@/components/flow/FlowMarkExhibit.vue";
import GeoRuleLink from "@/components/geo/GeoRuleLink.vue";
import RoutingRuleCard from "@/components/flow/RoutingRuleCard.vue";
import WanRuleEditModal from "./WanRuleEditModal.vue";

const { rule } = defineProps<{ rule: WanIpRuleConfig }>();
const emit = defineEmits<{ refresh: [] }>();
const { t } = useI18n();
const frontend = useFrontEndStore();
const showEditor = ref(false);
const name = computed(() => rule.name?.trim());

async function deleteRule() {
  if (rule.id) {
    await delete_dst_ip_rules_rule(rule.id);
    emit("refresh");
  }
}
</script>

<template>
  <RoutingRuleCard
    :title="name || rule.remark || t('common.no_remark')"
    :enabled="rule.enable"
    :priority="rule.index"
    :sources="rule.source"
    :delete-rule="deleteRule"
    @edit="showEditor = true"
  >
    <template #summary>
      <div class="egress">
        <span>{{ t("flow.rule_card.traffic_routing") }}</span>
        <FlowMarkExhibit :mark="rule.mark" :flow_id="rule.flow_id" />
      </div>
    </template>
    <template #source="{ source }">
      <div class="ip-source">
        <span class="source-kind">
          <n-tag
            size="small"
            :type="source.t === 'config' ? 'info' : 'success'"
            :bordered="false"
          >
            {{ source.t === "config" ? "CIDR" : "GeoIP" }}
          </n-tag>
          <GeoRuleLink
            v-if="source.t === 'geo_key' && source.name && source.key"
            :target="{ kind: 'ip', entry: source }"
          />
        </span>
        <div>
          <code v-if="source.t === 'config'"
            >{{ frontend.MASK_INFO(source.ip) }}/{{ source.prefix }}</code
          >
          <template v-else>
            <code
              >{{ frontend.MASK_INFO(source.name) }}/{{
                frontend.MASK_INFO(source.key)
              }}</code
            >
            <n-text
              v-if="source.attribute_key || source.inverse"
              depth="3"
              class="geo-options"
            >
              <span>{{ t("flow.wan_rule_card.stored_geo_options") }}</span>
              <span v-if="source.attribute_key"
                >@{{ frontend.MASK_INFO(source.attribute_key) }}</span
              >
              <span v-if="source.inverse">{{ t("common.inverse") }}</span>
            </n-text>
          </template>
        </div>
      </div>
    </template>
    <template #empty>
      <n-text class="empty-match" type="warning">
        <n-icon aria-hidden="true"><Warning /></n-icon>
        {{ t("flow.wan_rule_card.no_match_rules") }}
      </n-text>
    </template>
    <template v-if="name && rule.remark" #footer>
      <p class="remark">
        <span>{{ t("common.remark") }}</span
        >{{ rule.remark }}
      </p>
    </template>
  </RoutingRuleCard>
  <WanRuleEditModal
    v-model:show="showEditor"
    :flow_id="rule.flow_id"
    :id="rule.id ?? null"
    @refresh="emit('refresh')"
  />
</template>

<style scoped>
.egress {
  display: flex;
  flex: 1;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px 6px;
  min-width: 0;
}
.egress > span,
.remark span {
  font-size: 12px;
  color: var(--muted);
}
.egress > :deep(.n-flex) {
  min-width: 0;
  max-width: 100%;
}
.egress :deep(.n-tag) {
  height: auto;
  min-height: 22px;
  max-width: 100%;
  font-size: 12px;
  line-height: 1.4;
  white-space: normal;
}
.ip-source {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: baseline;
  column-gap: 4px;
}
.source-kind {
  display: inline-flex;
  align-items: center;
  gap: 3px;
}
.ip-source code {
  font-family: var(--font-mono);
}
.geo-options {
  display: flex;
  flex-wrap: wrap;
  gap: 0 4px;
  font-size: 12px;
}
.empty-match {
  display: flex;
  align-items: baseline;
  gap: 6px;
}
.remark {
  display: flex;
  gap: 8px;
  align-items: baseline;
  margin: 0 12px 12px;
  border-top: 1px solid var(--n-border-color);
  padding-top: 8px;
}
.remark span {
  flex: none;
}
</style>
