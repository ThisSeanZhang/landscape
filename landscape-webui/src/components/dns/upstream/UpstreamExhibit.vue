<script lang="ts" setup>
import { get_dns_upstream } from "@/api/dns_rule/upstream";
import type { DnsUpstreamConfig } from "@landscape-router/types/api/schemas";
import { watch, ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();
const props = defineProps<{ rule_id: string }>();
const rule = ref<DnsUpstreamConfig>();
const pending = ref(false);
watch(
  () => props.rule_id,
  async (id, _, onCleanup) => {
    let current = true;
    onCleanup(() => {
      current = false;
    });
    rule.value = undefined;
    pending.value = Boolean(id);
    if (!id) return;
    try {
      const upstream = await get_dns_upstream(id);
      if (current) rule.value = upstream;
    } catch {
      // The API client reports the error. Keep the configured ID visible.
    } finally {
      if (current) pending.value = false;
    }
  },
  { immediate: true },
);
</script>

<template>
  <n-skeleton v-if="pending" text width="7em" />
  <n-popover v-else-if="rule" trigger="hover">
    <template #trigger>
      <span>{{
        [rule.name?.trim(), rule.remark?.trim()].filter(Boolean).join(" - ") ||
        t("common.unnamed")
      }}</span>
    </template>
    <DnsUpstreamCard :show_action="false" :rule="rule" />
  </n-popover>
  <span v-else>{{ t("dns.upstream_card.no_upstream", { rule_id }) }}</span>
</template>
