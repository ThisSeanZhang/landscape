<script lang="ts" setup>
import { get_dns_redirects } from "@/api/dns_rule/redirect";
import { DNSRedirectRule } from "@/rust_bindings/common/dns_redirect";
import { ref, onMounted } from "vue";

const redirect_rules = ref<DNSRedirectRule[]>([]);

async function refresh_rules() {
  redirect_rules.value = await get_dns_redirects();
}

onMounted(async () => {
  await refresh_rules();
});

const show_edit_modal = ref(false);
</script>
<template>
  <n-flex vertical style="flex: 1">
    <n-flex>
      <n-button @click="show_edit_modal = true">创建</n-button>
    </n-flex>
    <n-flex vertical="false" style="flex: 1">
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 1200:3 1600:3">
        <n-grid-item v-for="rule in redirect_rules" :key="rule.id">
          <DnsRedirectCard @refresh="refresh_rules()" :rule="rule">
          </DnsRedirectCard>
        </n-grid-item>
      </n-grid>
    </n-flex>

    <DnsRedirectEditModal
      @refresh="refresh_rules"
      v-model:show="show_edit_modal"
    >
    </DnsRedirectEditModal>
  </n-flex>
</template>
