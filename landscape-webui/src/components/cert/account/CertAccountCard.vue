<script setup lang="ts">
import { ref } from "vue";
import type { CertAccountConfig } from "@landscape-router/types/api/schemas";
import {
  delete_cert_account,
  register_cert_account,
  verify_cert_account,
  deactivate_cert_account_api,
} from "@/api/cert/account";
import { useI18n } from "vue-i18n";

type Props = {
  rule: CertAccountConfig;
};

const props = defineProps<Props>();
const emit = defineEmits(["refresh"]);
const { t } = useI18n();

const show_edit_modal = ref(false);
const register_spin = ref(false);
const verify_spin = ref(false);
const deactivate_spin = ref(false);

function provider_label(config?: CertAccountConfig["provider_config"]) {
  if (!config) return "-";
  if (typeof config === "string") {
    if (config === "lets_encrypt") return t("cert.provider_lets_encrypt");
    return config;
  }
  if (typeof config === "object") {
    if ("zero_ssl" in config) return t("cert.provider_zero_ssl");
    const keys = Object.keys(config);
    if (keys.length > 0) return keys[0];
  }
  return "-";
}

function status_type(status?: string) {
  switch (status) {
    case "registered":
      return "success";
    case "registering":
      return "warning";
    case "error":
      return "error";
    default:
      return "default";
  }
}

function status_label(status?: string) {
  switch (status) {
    case "unregistered":
      return t("cert.status_unregistered");
    case "registering":
      return t("cert.status_registering");
    case "registered":
      return t("cert.status_registered");
    case "error":
      return t("cert.status_error");
    default:
      return status ?? "-";
  }
}

async function del() {
  if (props.rule.id) {
    await delete_cert_account(props.rule.id);
    emit("refresh");
  }
}

async function register() {
  if (!props.rule.id) return;
  try {
    register_spin.value = true;
    await register_cert_account(props.rule.id);
    emit("refresh");
  } finally {
    register_spin.value = false;
  }
}

async function verify() {
  if (!props.rule.id) return;
  try {
    verify_spin.value = true;
    await verify_cert_account(props.rule.id);
    emit("refresh");
  } finally {
    verify_spin.value = false;
  }
}

async function deactivate() {
  if (!props.rule.id) return;
  try {
    deactivate_spin.value = true;
    await deactivate_cert_account_api(props.rule.id);
    emit("refresh");
  } finally {
    deactivate_spin.value = false;
  }
}
</script>

<template>
  <n-card size="small">
    <template #header>
      <n-ellipsis>{{ rule.name }}</n-ellipsis>
    </template>

    <n-descriptions
      label-style="width: 90px"
      bordered
      label-placement="left"
      :column="1"
      size="small"
    >
      <n-descriptions-item :label="t('cert.account_provider')">
        {{ provider_label(rule.provider_config) }}
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.account_email')">
        {{ rule.email }}
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.account_status')">
        <n-tag size="small" :type="status_type(rule.status)">
          {{ status_label(rule.status) }}
        </n-tag>
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.account_staging')">
        <n-tag size="small" :type="rule.use_staging ? 'warning' : 'default'">
          {{ rule.use_staging ? t("common.enable") : t("common.disable") }}
        </n-tag>
      </n-descriptions-item>
    </n-descriptions>

    <template #header-extra>
      <n-flex>
        <n-button
          v-if="rule.status === 'unregistered' || rule.status === 'error'"
          size="small"
          type="success"
          secondary
          :loading="register_spin"
          @click="register()"
        >
          {{ t("cert.action_register") }}
        </n-button>
        <n-button
          v-if="rule.status === 'registered'"
          size="small"
          type="info"
          secondary
          :loading="verify_spin"
          @click="verify()"
        >
          {{ t("cert.action_verify") }}
        </n-button>
        <n-popconfirm
          v-if="rule.status === 'registered'"
          @positive-click="deactivate()"
        >
          <template #trigger>
            <n-button
              size="small"
              type="warning"
              secondary
              :loading="deactivate_spin"
            >
              {{ t("cert.action_deactivate") }}
            </n-button>
          </template>
          {{ t("cert.confirm_deactivate") }}
        </n-popconfirm>
        <n-button
          size="small"
          type="warning"
          secondary
          @click="show_edit_modal = true"
        >
          {{ t("common.edit") }}
        </n-button>
        <n-popconfirm @positive-click="del()">
          <template #trigger>
            <n-button size="small" type="error" secondary>
              {{ t("common.delete") }}
            </n-button>
          </template>
          {{ t("common.confirm_delete") }}
        </n-popconfirm>
      </n-flex>
    </template>
  </n-card>

  <CertAccountEditModal
    @refresh="emit('refresh')"
    :rule_id="rule.id ?? null"
    v-model:show="show_edit_modal"
  />
</template>
