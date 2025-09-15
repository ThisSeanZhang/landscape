<script setup lang="ts">
import { get_dns_upstreams } from "@/api/dns_rule/upstream";
import { DnsUpstreamConfig } from "@/rust_bindings/common/dns";
import { computed, onMounted, ref } from "vue";

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
    style="width: 50%"
    v-model:value="upstream_id"
    filterable
    placeholder="重定向的流 ID"
    :options="upstream_options"
    :loading="flow_search_loading"
    remote
    @search="search_upstreams"
  />
</template>
