<script lang="ts" setup>
import { get_gateway_rules, get_gateway_status } from "@/api/gateway";
import type {
  HttpUpstreamRuleConfig,
  GatewayStatus,
} from "@landscape-router/types/api/schemas";
import { ref, onMounted } from "vue";
import { useI18n } from "vue-i18n";

const rules = ref<HttpUpstreamRuleConfig[]>([]);
const status = ref<GatewayStatus>();
const { t } = useI18n();

async function refresh_rules() {
  rules.value = await get_gateway_rules();
}

async function refresh_status() {
  status.value = await get_gateway_status();
}

onMounted(async () => {
  await Promise.all([refresh_rules(), refresh_status()]);
});

const show_edit_modal = ref(false);
</script>
<template>
  <n-flex vertical style="flex: 1">
    <n-flex align="center" justify="space-between">
      <n-flex>
        <n-button @click="show_edit_modal = true">{{
          t("common.create")
        }}</n-button>
      </n-flex>
      <n-flex v-if="status" align="center" :size="16">
        <n-tag :type="status.running ? 'success' : 'default'" size="small">
          {{
            status.running
              ? t("gateway.status_running")
              : t("gateway.status_stopped")
          }}
        </n-tag>
        <n-text depth="3" style="font-size: 13px">
          HTTP: {{ status.http_port }} | HTTPS: {{ status.https_port }}
        </n-text>
      </n-flex>
    </n-flex>
    <n-flex>
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 1200:3 1600:3">
        <n-grid-item v-for="rule in rules" :key="rule.id">
          <GatewayRuleCard @refresh="refresh_rules()" :rule="rule" />
        </n-grid-item>
      </n-grid>
    </n-flex>

    <GatewayRuleEditModal
      @refresh="refresh_rules"
      v-model:show="show_edit_modal"
    />
  </n-flex>
</template>
