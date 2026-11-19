<script lang="ts" setup>
import {
  get_gateway_config_edit,
  get_gateway_rules,
  get_gateway_status,
  restart_gateway,
  update_gateway_config,
  type GatewayStatus,
} from "@/api/gateway";
import {
  ServiceStatusType,
  get_service_status_label,
  get_service_status_tag_type,
} from "@/lib/services";
import type { HttpUpstreamRuleConfig } from "@landscape-router/types/api/schemas";
import { Settings } from "@vicons/carbon";
import { useTimeoutPoll } from "@vueuse/core";
import { useMessage } from "naive-ui";
import { onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";

const rules = ref<HttpUpstreamRuleConfig[]>([]);
const status = ref<GatewayStatus>();
let statusRequestId = 0;
const gatewayEnabled = ref(false);
const httpPort = ref<number | null>(80);
const httpsPort = ref<number | null>(443);
const configHash = ref("");
const savingConfig = ref(false);
const restartingGateway = ref(false);
const show_edit_modal = ref(false);
const show_settings = ref(false);
const { t } = useI18n();
const message = useMessage();

async function refresh_rules() {
  rules.value = await get_gateway_rules();
}

async function refresh_config() {
  const { gateway, hash } = await get_gateway_config_edit();
  gatewayEnabled.value = gateway.enable ?? false;
  httpPort.value = gateway.http_port ?? 80;
  httpsPort.value = gateway.https_port ?? 443;
  configHash.value = hash;
}

async function refresh_status() {
  const requestId = ++statusRequestId;
  const result = await get_gateway_status();
  if (requestId === statusRequestId) status.value = result;
}

async function refreshAll() {
  await Promise.all([refresh_rules(), refresh_status(), refresh_config()]);
}

const statusPoll = useTimeoutPoll(
  () =>
    refresh_status().catch((error) =>
      console.error("Failed to refresh gateway status", error),
    ),
  () => (status.value?.status.t === ServiceStatusType.Running ? 10_000 : 2000),
  { immediate: false },
);

function gateway_status_label(statusValue: GatewayStatus | undefined) {
  return get_service_status_label(statusValue?.status, t);
}

function gateway_status_tag_type(statusValue: GatewayStatus | undefined) {
  return get_service_status_tag_type(statusValue?.status);
}

async function saveGatewayConfig(showSuccess = true) {
  await update_gateway_config({
    new_gateway: {
      enable: gatewayEnabled.value,
      http_port: httpPort.value ?? undefined,
      https_port: httpsPort.value ?? undefined,
    },
    expected_hash: configHash.value,
  });
  await refresh_config();
  if (showSuccess) {
    show_settings.value = false;
    message.success(t("config.save_success"));
  }
}

async function handleSaveGatewayConfig() {
  savingConfig.value = true;
  try {
    await saveGatewayConfig();
  } catch (e: any) {
    if (e?.error_id === "config.conflict" || e?.response?.status === 409) {
      message.error(t("config.conflict"));
    } else if (!e?.error_id) {
      message.error(t("config.save_failed") + ": " + e.message);
    }
  } finally {
    savingConfig.value = false;
  }
}

async function handleSaveAndRestartGateway() {
  restartingGateway.value = true;
  try {
    await saveGatewayConfig(false);
    const restarted = await restart_gateway();
    // A status read started before the restart can finish after it.
    ++statusRequestId;
    status.value = restarted;
    show_settings.value = false;
    message.success(t("gateway.restart_success"));
  } catch (e: any) {
    if (e?.error_id === "config.conflict" || e?.response?.status === 409) {
      message.error(t("config.conflict"));
    } else if (!e?.error_id) {
      message.error(t("gateway.restart_failed") + ": " + e.message);
    }
    await refresh_status().catch((refreshError) => {
      console.error("Failed to refresh gateway status", refreshError);
    });
  } finally {
    restartingGateway.value = false;
  }
}

onMounted(async () => {
  try {
    await refreshAll();
  } catch (e) {
    message.error(t("config.load_failed"));
    console.error(e);
  }
});

watch(
  () => status.value?.status.t,
  (phase) => {
    if (
      phase === ServiceStatusType.Staring ||
      phase === ServiceStatusType.Running ||
      phase === ServiceStatusType.Stopping ||
      phase === ServiceStatusType.Failed
    ) {
      statusPoll.resume();
    } else {
      statusPoll.pause();
    }
  },
);
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
        <n-tag :type="gateway_status_tag_type(status)" size="small">
          {{ gateway_status_label(status) }}
        </n-tag>
        <n-text depth="3" style="font-size: 13px">
          HTTP: {{ status.http_port }} | HTTPS: {{ status.https_port }} |
          {{ t("gateway.rule_count") }}: {{ status.rule_count }}
        </n-text>
        <n-popover
          v-model:show="show_settings"
          trigger="click"
          placement="bottom-end"
        >
          <template #trigger>
            <n-button quaternary circle size="small">
              <template #icon>
                <n-icon :component="Settings" />
              </template>
            </n-button>
          </template>

          <n-flex
            vertical
            size="small"
            style="padding: 4px; min-width: 320px; max-width: 360px"
          >
            <n-text strong>{{ t("gateway.runtime_title") }}</n-text>
            <n-form label-placement="top">
              <n-form-item :label="t('gateway.enabled')">
                <n-switch v-model:value="gatewayEnabled" />
                <template #feedback>
                  {{ t("gateway.enabled_desc") }}
                </template>
              </n-form-item>
              <n-grid x-gap="12" cols="2">
                <n-grid-item>
                  <n-form-item :label="t('gateway.http_port')">
                    <n-input-number
                      v-model:value="httpPort"
                      :min="1"
                      :max="65535"
                      style="width: 100%"
                    />
                    <template #feedback>
                      {{ t("gateway.http_port_desc") }}
                    </template>
                  </n-form-item>
                </n-grid-item>
                <n-grid-item>
                  <n-form-item :label="t('gateway.https_port')">
                    <n-input-number
                      v-model:value="httpsPort"
                      :min="1"
                      :max="65535"
                      style="width: 100%"
                    />
                    <template #feedback>
                      {{ t("gateway.https_port_desc") }}
                    </template>
                  </n-form-item>
                </n-grid-item>
              </n-grid>
            </n-form>

            <n-alert type="info" :show-icon="false">
              {{ t("gateway.restart_hint") }}
            </n-alert>

            <n-flex justify="end" :size="8">
              <n-button
                :loading="savingConfig"
                @click="handleSaveGatewayConfig"
              >
                {{ t("gateway.save_runtime") }}
              </n-button>
              <n-button
                type="primary"
                :disabled="status?.supported === false"
                :loading="restartingGateway"
                @click="handleSaveAndRestartGateway"
              >
                {{ t("gateway.save_and_restart") }}
              </n-button>
            </n-flex>
          </n-flex>
        </n-popover>
      </n-flex>
    </n-flex>
    <n-alert
      v-if="status?.last_error"
      type="error"
      :title="t('gateway.service_error')"
    >
      <n-flex vertical :size="4">
        <n-text style="white-space: pre-wrap; overflow-wrap: anywhere">
          {{ status.last_error }}
        </n-text>
        <n-text depth="3">{{ t("gateway.recovery_hint") }}</n-text>
      </n-flex>
    </n-alert>
    <n-flex>
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 1200:3 1600:3">
        <n-grid-item v-for="rule in rules" :key="rule.id">
          <GatewayRuleCard @refresh="refreshAll" :rule="rule" />
        </n-grid-item>
      </n-grid>
    </n-flex>

    <GatewayRuleEditModal
      @refresh="refreshAll"
      v-model:show="show_edit_modal"
    />
  </n-flex>
</template>
