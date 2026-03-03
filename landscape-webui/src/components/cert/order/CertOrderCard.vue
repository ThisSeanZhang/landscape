<script setup lang="ts">
import { ref } from "vue";
import type { CertConfig } from "@landscape-router/types/api/schemas";
import { delete_cert } from "@/api/cert/order";
import { useI18n } from "vue-i18n";

type Props = {
  rule: CertConfig;
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

function cert_type_label(ct?: CertConfig["cert_type"]) {
  if (!ct) return "-";
  if (ct.t === "acme") return t("cert.type_acme");
  if (ct.t === "manual") return t("cert.type_manual");
  return "-";
}

function format_ts(ts?: number | null) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleDateString();
}

async function del() {
  if (props.rule.id) {
    await delete_cert(props.rule.id);
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
      <n-descriptions-item :label="t('cert.cert_type')">
        {{ cert_type_label(rule.cert_type) }}
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.cert_domains')">
        <n-flex size="small">
          <n-tag v-for="d in rule.domains" :key="d" size="small">
            {{ d }}
          </n-tag>
        </n-flex>
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.cert_status')">
        <n-tag size="small" :type="status_type(rule.status)">
          {{ status_label(rule.status) }}
        </n-tag>
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.cert_issued_at')">
        {{ format_ts(rule.issued_at) }}
      </n-descriptions-item>

      <n-descriptions-item :label="t('cert.cert_expires')">
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
