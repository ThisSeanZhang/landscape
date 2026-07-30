<script lang="ts" setup>
import { get_dns_upstream } from "@/api/dns_rule/upstream";
import type { DnsUpstreamConfig } from "@landscape-router/types/api/schemas";
import { onMounted, watch, ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();

type Props = {
  rule_id: string;
};

const props = defineProps<Props>();

onMounted(async () => {
  await refresh();
});

watch(
  () => props.rule_id,
  async () => {
    await refresh();
  },
);

const rule = ref<DnsUpstreamConfig>();
async function refresh() {
  rule.value = await get_dns_upstream(props.rule_id);
}
</script>
<template>
  <n-popover v-if="rule" trigger="hover">
    <template #trigger>
      {{ rule.remark }}
    </template>
    <DnsUpstreamCard :show_action="false" :rule="rule"></DnsUpstreamCard>
    <!-- <span>{{ rule }}</span> -->
  </n-popover>
  <n-flex v-else>
    {{ t("dns.upstream_card.no_upstream", { rule_id: rule_id }) }}</n-flex
  >
</template>
