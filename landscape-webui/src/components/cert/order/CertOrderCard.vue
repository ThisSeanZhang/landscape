<script setup lang="ts">
import { ref } from "vue";
import type { CertOrderConfig } from "@landscape-router/types/api/schemas";
import { delete_cert_order } from "@/api/cert/order";
import { useI18n } from "vue-i18n";

type Props = {
  rule: CertOrderConfig;
};

const props = defineProps<Props>();
const emit = defineEmits(["refresh"]);
const { t } = useI18n();

const show_edit_modal = ref(false);

function status_type(status?: string) {
  switch (status) {
    case "valid":
      return "success";
    case "pending":
    case "ready":
    case "processing":
      return "warning";
    case "invalid":
    case "expired":
    case "revoked":
      return "error";
    default:
      return "default";
  }
}

function status_label(status?: string) {
  const key = `cert.status_${status}`;
  return t(key);
}

function challenge_label(ct?: CertOrderConfig["challenge_type"]) {
  if (!ct || typeof ct !== "object") return "-";
  if ("http" in ct) return t("cert.challenge_http");
  if ("dns" in ct) return t("cert.challenge_dns");
  return "-";
}

function key_type_label(kt?: string) {
  switch (kt) {
    case "ecdsa_p256":
      return t("cert.key_ecdsa_p256");
    case "ecdsa_p384":
      return t("cert.key_ecdsa_p384");
    case "rsa2048":
      return t("cert.key_rsa2048");
    case "rsa4096":
      return t("cert.key_rsa4096");
    default:
      return kt ?? "-";
  }
}

function format_ts(ts?: number | null) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleDateString();
}

async function del() {
  if (props.rule.id) {
    await delete_cert_order(props.rule.id);
    emit("refresh");
  }
}
</script>

<template>
  <n-card size="small">
    <template #header>
      <n-ellipsis>{{ rule.name }}</n-ellipsis>
    </template>

    <n-descriptions
      label-style="width: 110px"
      bordered
      label-placement="left"
      :column="1"
      size="small"
    >
      <n-descriptions-item :label="t('cert.order_domains')">
        <n-flex size="small">
          <n-tag v-for="d in rule.domains" :key="d" size="small">
            {{ d }}
          </n-tag>
        </n-flex>
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.order_status')">
        <n-tag size="small" :type="status_type(rule.status)">
          {{ status_label(rule.status) }}
        </n-tag>
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.order_challenge')">
        {{ challenge_label(rule.challenge_type) }}
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.order_key_type')">
        {{ key_type_label(rule.key_type) }}
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.order_auto_renew')">
        <n-tag size="small" :type="rule.auto_renew ? 'success' : 'default'">
          {{ rule.auto_renew ? t("common.enable") : t("common.disable") }}
        </n-tag>
      </n-descriptions-item>

      <n-descriptions-item
        v-if="rule.auto_renew"
        :label="t('cert.order_renew_before_days')"
      >
        {{ rule.renew_before_days ?? 30 }} {{ t("cert.days") }}
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.order_issued_at')">
        {{ format_ts(rule.issued_at) }}
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.order_expires')">
        {{ format_ts(rule.expires_at) }}
      </n-descriptions-item>
    </n-descriptions>

    <template #header-extra>
      <n-flex>
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

  <CertOrderEditModal
    @refresh="emit('refresh')"
    :rule_id="rule.id ?? null"
    v-model:show="show_edit_modal"
  />
</template>
