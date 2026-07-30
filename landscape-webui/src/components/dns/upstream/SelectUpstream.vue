<script setup lang="ts">
import { get_dns_upstreams } from "@/api/dns_rule/upstream";
import type { DnsUpstreamConfig } from "@landscape-router/types/api/schemas";
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();

const upstream_id = defineModel<string>("upstream_id", { required: true });

onMounted(async () => {
  await search_upstreams();
});

const all_upstream = ref<DnsUpstreamConfig[]>([]);
const upstream_options = computed(() => {
  return all_upstream.value
    .filter((e) => e.id)
    .map((e) => ({
      value: e.id,
      label: e.remark ? `${e.remark}` : e.id,
    }));
});

const flow_search_loading = ref(false);
async function search_upstreams() {
  all_upstream.value = await get_dns_upstreams();
}
</script>

<template>
  <n-select
    v-model:value="upstream_id"
    filterable
    :placeholder="t('dns.select_upstream.redirect_flow_id')"
    :options="upstream_options"
    :loading="flow_search_loading"
    remote
    @search="search_upstreams"
  />
</template>
