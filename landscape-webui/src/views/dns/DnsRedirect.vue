<script lang="ts" setup>
import { get_dns_redirects } from "@/api/dns_rule/redirect";
import type { DNSRedirectRule } from "@landscape-router/types/api/schemas";
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
    <n-flex>
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 1200:3 1600:3">
        <n-grid-item v-for="rule in redirect_rules" :key="rule.id">
          <DnsRedirectCard @refresh="refresh_rules()" :rule="rule">
          </DnsRedirectCard>
        </n-grid-item>
      </n-grid>
    </n-flex>

    <DnsRedirectEditModal
      :rule_id="null"
      @refresh="refresh_rules"
      v-model:show="show_edit_modal"
    >
    </DnsRedirectEditModal>
  </n-flex>
</template>
