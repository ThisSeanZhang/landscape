<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { CertConfig } from "@landscape-router/types/api/schemas";
import type { CertParsedInfo } from "@landscape-router/types/api/schemas";
import { get_cert_info } from "@/api/cert/order";
import { useI18n } from "vue-i18n";

const show = defineModel<boolean>("show", { required: true });

const props = defineProps<{
  cert: CertConfig | null;
}>();

const { t } = useI18n();
const parsed_info = ref<CertParsedInfo | null>(null);
const parsed_loading = ref(false);
const parsed_error = ref("");
const collapse_names = ref<string[]>([]);

function format_ts(ts?: number | null) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString();
}

function download_text_file(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function download_cert() {
  if (!props.cert) return;
  const cert = props.cert.certificate ?? "";
  const chain = props.cert.certificate_chain ?? "";
  const content = [cert.trim(), chain.trim()].filter(Boolean).join("\n\n");
  if (!content) return;
  const name = `${props.cert.name || "certificate"}.pem`;
  download_text_file(name, content);
}

function download_key() {
  if (!props.cert?.private_key) return;
  const name = `${props.cert.name || "private-key"}.key.pem`;
  download_text_file(name, props.cert.private_key);
}

const status_key = computed(() => {
  if (!props.cert?.status) return "-";
  return t(`cert.status_${props.cert.status}`);
});

const cert_type_key = computed(() => {
  const ct = props.cert?.cert_type;
  if (!ct) return "-";
  return ct.t === "acme" ? t("cert.type_acme") : t("cert.type_manual");
});

async function fetch_parsed_info() {
  if (!props.cert?.id) {
    parsed_info.value = null;
    parsed_error.value = "";
    return;
  }
  parsed_loading.value = true;
  parsed_error.value = "";
  try {
    parsed_info.value = await get_cert_info(props.cert.id);
  } catch (e: any) {
    parsed_info.value = null;
    parsed_error.value = e?.message || t("cert.cert_parse_failed");
  } finally {
    parsed_loading.value = false;
  }
}

watch(
  [show, () => props.cert?.id],
  ([visible]) => {
    if (visible) {
      fetch_parsed_info();
    }
  },
  { immediate: true },
);
</script>

<template>
  <n-modal
    v-model:show="show"
    preset="card"
    class="custom-card"
    style="width: min(960px, 92vw)"
    :title="t('cert.cert_info_title')"
    :bordered="false"
  >
    <n-empty v-if="!cert" />

    <n-flex v-else vertical :size="12">
      <n-descriptions bordered :column="2" label-placement="left">
        <n-descriptions-item :label="t('cert.cert_name')">
          {{ cert.name || "-" }}
        </n-descriptions-item>
        <n-descriptions-item :label="t('cert.cert_type')">
          {{ cert_type_key }}
        </n-descriptions-item>
        <n-descriptions-item :label="t('cert.cert_status')">
          {{ status_key }}
        </n-descriptions-item>
        <n-descriptions-item :label="t('cert.cert_issued_at')">
          {{ format_ts(cert.issued_at) }}
        </n-descriptions-item>
        <n-descriptions-item :label="t('cert.cert_expires')">
          {{ format_ts(cert.expires_at) }}
        </n-descriptions-item>
      </n-descriptions>

      <n-card size="small">
        <template #header>{{ t("cert.cert_domains") }}</template>
        <n-flex size="small" wrap>
          <n-tag
            v-for="domain in cert.domains"
            :key="domain"
            size="small"
            bordered
          >
            {{ domain }}
          </n-tag>
          <span v-if="!cert.domains?.length">-</span>
        </n-flex>
      </n-card>

      <n-card size="small">
        <template #header>{{ t("cert.cert_parsed_title") }}</template>
        <template #header-extra>
          <n-flex size="small">
            <n-button
              size="small"
              secondary
              :disabled="!(cert?.certificate || cert?.certificate_chain)"
              @click="download_cert"
            >
              {{ t("cert.download_cert") }}
            </n-button>
            <n-button
              size="small"
              secondary
              :disabled="!cert?.private_key"
              @click="download_key"
            >
              {{ t("cert.download_key") }}
            </n-button>
          </n-flex>
        </template>
        <n-spin :show="parsed_loading">
          <n-alert
            v-if="parsed_error"
            type="warning"
            :show-icon="true"
            style="margin-bottom: 8px"
          >
            {{ parsed_error }}
          </n-alert>
          <n-descriptions
            v-if="parsed_info"
            bordered
            :column="1"
            label-placement="left"
          >
            <n-descriptions-item :label="t('cert.cert_subject')">
              {{ parsed_info.subject || "-" }}
            </n-descriptions-item>
            <n-descriptions-item :label="t('cert.cert_issuer')">
              {{ parsed_info.issuer || "-" }}
            </n-descriptions-item>
            <n-descriptions-item :label="t('cert.cert_serial_number')">
              {{ parsed_info.serial_number || "-" }}
            </n-descriptions-item>
            <n-descriptions-item :label="t('cert.cert_signature_algorithm')">
              {{ parsed_info.signature_algorithm || "-" }}
            </n-descriptions-item>
            <n-descriptions-item :label="t('cert.cert_not_before')">
              {{ format_ts(parsed_info.not_before) }}
            </n-descriptions-item>
            <n-descriptions-item :label="t('cert.cert_not_after')">
              {{ format_ts(parsed_info.not_after) }}
            </n-descriptions-item>
            <n-descriptions-item :label="t('cert.cert_fingerprint_sha256')">
              {{ parsed_info.fingerprint_sha256 || "-" }}
            </n-descriptions-item>
            <n-descriptions-item :label="t('cert.cert_san')">
              <n-flex size="small" wrap>
                <n-tag
                  v-for="domain in parsed_info.subject_alt_names"
                  :key="domain"
                  size="small"
                >
                  {{ domain }}
                </n-tag>
                <span v-if="!parsed_info.subject_alt_names?.length">-</span>
              </n-flex>
            </n-descriptions-item>
          </n-descriptions>
          <n-empty
            v-else-if="!parsed_error"
            :description="t('cert.no_cert_content')"
          />
        </n-spin>
      </n-card>

      <n-collapse v-model:expanded-names="collapse_names">
        <n-collapse-item :title="t('cert.raw_pem_title')" name="raw_pem">
          <n-flex vertical :size="8">
            <n-form-item :label="t('cert.upload_cert')">
              <n-input
                :value="cert.certificate || ''"
                type="textarea"
                :rows="6"
                readonly
                :placeholder="t('cert.no_cert_content')"
              />
            </n-form-item>

            <n-form-item :label="t('cert.upload_chain')">
              <n-input
                :value="cert.certificate_chain || ''"
                type="textarea"
                :rows="4"
                readonly
                :placeholder="t('cert.no_cert_content')"
              />
            </n-form-item>

            <n-form-item :label="t('cert.cert_private_key')">
              <n-input
                :value="cert.private_key || ''"
                type="textarea"
                :rows="6"
                readonly
                :placeholder="t('cert.no_cert_content')"
              />
            </n-form-item>
          </n-flex>
        </n-collapse-item>
      </n-collapse>

      <n-alert v-if="cert.status_message" type="warning" :show-icon="true">
        <template #header>{{ t("cert.cert_status_message") }}</template>
        {{ cert.status_message }}
      </n-alert>
    </n-flex>

    <template #footer>
      <n-flex justify="end">
        <n-button @click="show = false">{{ t("common.close") }}</n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
