<script lang="ts" setup>
import {
  delete_dns_provider_profile,
  get_dns_provider_profiles,
  push_dns_provider_profile,
  validate_dns_provider_profile_credentials,
} from "@/api/domain/provider_profile";
import type {
  DnsProviderCredentialCheckRequest,
  DnsProviderConfig,
  DnsProviderProfile,
} from "@landscape-router/types/api/schemas";
import { computed, h, onMounted, ref } from "vue";
import {
  NButton,
  NPopconfirm,
  NTag,
  useMessage,
  type DataTableColumns,
} from "naive-ui";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useI18n } from "vue-i18n";

const { t } = useI18n();
const message = useMessage();
const frontEndStore = useFrontEndStore();
const items = ref<DnsProviderProfile[]>([]);
const loading = ref(false);
const showModal = ref(false);
const saving = ref(false);
const validating = ref(false);
const validatingIds = ref<Set<string>>(new Set());
const editingId = ref<string | null>(null);
const formRef = ref();
const form = ref<DnsProviderProfile>({
  name: "",
  provider_config: { cloudflare: { api_token: "" } },
  ddns_default_ttl: defaultDdnsTtlForProvider("cloudflare"),
  remark: "",
});
const providerType = ref("cloudflare");

const providerOptions = [
  { label: "Cloudflare", value: "cloudflare" },
  { label: "Aliyun", value: "aliyun" },
  { label: "Tencent", value: "tencent" },
  { label: "AWS Route53", value: "aws" },
  { label: "Google Cloud DNS", value: "google" },
];

function defaultDdnsTtlForProvider(type: string): number {
  switch (type) {
    case "aliyun":
      return 600;
    case "tencent":
      return 600;
    default:
      return 120;
  }
}

const rules = {
  name: {
    required: true,
    message: () => t("dns_provider.profile_name_required"),
    trigger: ["input", "blur"],
  },
};

function getProviderType(config?: DnsProviderConfig): string {
  if (!config) {
    return "cloudflare";
  }
  if (typeof config === "string") {
    return "cloudflare";
  }
  const keys = Object.keys(config);
  return keys[0] ?? "cloudflare";
}

function buildProviderConfig(
  type: string,
  current?: DnsProviderConfig,
): DnsProviderConfig {
  const currentObj = typeof current === "object" && current ? current : {};
  switch (type) {
    case "cloudflare":
      return {
        cloudflare: {
          api_token: (currentObj as any).cloudflare?.api_token ?? "",
        },
      };
    case "aliyun":
      return {
        aliyun: {
          access_key_id: (currentObj as any).aliyun?.access_key_id ?? "",
          access_key_secret:
            (currentObj as any).aliyun?.access_key_secret ?? "",
        },
      };
    case "tencent":
      return {
        tencent: {
          secret_id: (currentObj as any).tencent?.secret_id ?? "",
          secret_key: (currentObj as any).tencent?.secret_key ?? "",
        },
      };
    case "aws":
      return {
        aws: {
          access_key_id: (currentObj as any).aws?.access_key_id ?? "",
          secret_access_key: (currentObj as any).aws?.secret_access_key ?? "",
          region: (currentObj as any).aws?.region ?? "us-east-1",
        },
      };
    case "google":
      return {
        google: {
          service_account_json:
            (currentObj as any).google?.service_account_json ?? "",
        },
      };
    default:
      return {
        cloudflare: {
          api_token: (currentObj as any).cloudflare?.api_token ?? "",
        },
      };
  }
}

function setProviderType(type: string) {
  const previousType = providerType.value;
  providerType.value = type;
  form.value.provider_config = buildProviderConfig(
    type,
    form.value.provider_config,
  );

  const previousDefaultTtl = defaultDdnsTtlForProvider(previousType);
  if (
    form.value.ddns_default_ttl == null ||
    form.value.ddns_default_ttl === previousDefaultTtl
  ) {
    form.value.ddns_default_ttl = defaultDdnsTtlForProvider(type);
  }
}

function providerLabel(config?: DnsProviderConfig) {
  const type = getProviderType(config);
  return providerOptions.find((item) => item.value === type)?.label ?? type;
}

function resetForm(item?: DnsProviderProfile) {
  form.value = item
    ? {
        ...item,
        remark: item.remark ?? "",
        ddns_default_ttl:
          item.ddns_default_ttl ??
          defaultDdnsTtlForProvider(getProviderType(item.provider_config)),
      }
    : {
        name: "",
        provider_config: { cloudflare: { api_token: "" } },
        ddns_default_ttl: defaultDdnsTtlForProvider("cloudflare"),
        remark: "",
      };
  editingId.value = item?.id ?? null;
  providerType.value = getProviderType(form.value.provider_config);
}

async function refresh() {
  loading.value = true;
  try {
    items.value = await get_dns_provider_profiles();
  } finally {
    loading.value = false;
  }
}

async function save() {
  await formRef.value?.validate();
  saving.value = true;
  try {
    await push_dns_provider_profile({
      ...form.value,
      id: editingId.value ?? undefined,
      provider_config:
        form.value.provider_config ?? buildProviderConfig(providerType.value),
      ddns_default_ttl: form.value.ddns_default_ttl || undefined,
      remark: form.value.remark || undefined,
    });
    showModal.value = false;
    await refresh();
  } finally {
    saving.value = false;
  }
}

async function remove(id: string) {
  await delete_dns_provider_profile(id);
  await refresh();
}

async function validateCredentials() {
  validating.value = true;
  try {
    await runProviderValidation(
      form.value.provider_config ??
        buildProviderConfig(providerType.value, form.value.provider_config),
    );
  } catch (error: any) {
    message.error(
      error?.message || t("dns_provider.provider_validation_failed"),
    );
  } finally {
    validating.value = false;
  }
}

async function runProviderValidation(providerConfig: DnsProviderConfig) {
  const result = await validate_dns_provider_profile_credentials({
    provider_config: providerConfig,
  } as DnsProviderCredentialCheckRequest);
  message.success(result.message);
}

async function validateRowCredentials(row: DnsProviderProfile) {
  if (!row.id) return;
  validatingIds.value.add(row.id);
  try {
    await runProviderValidation(
      row.provider_config ??
        buildProviderConfig(
          getProviderType(row.provider_config),
          row.provider_config,
        ),
    );
  } catch (error: any) {
    message.error(
      error?.message || t("dns_provider.provider_validation_failed"),
    );
  } finally {
    validatingIds.value.delete(row.id);
  }
}

const columns = computed<DataTableColumns<DnsProviderProfile>>(() => [
  {
    title: t("dns_provider.profile_name"),
    key: "name",
    minWidth: 140,
    render: (row) => frontEndStore.MASK_INFO(row.name),
  },
  {
    title: t("dns_provider.provider"),
    key: "provider_config",
    width: 140,
    render: (row) =>
      h(
        NTag,
        {
          size: "small",
          type: row.provider_config === "manual" ? "default" : "info",
        },
        () => providerLabel(row.provider_config),
      ),
  },
  {
    title: t("dns_provider.ddns_default_ttl"),
    key: "ddns_default_ttl",
    width: 120,
    render: (row) => row.ddns_default_ttl ?? 120,
  },
  {
    title: t("common.remark"),
    key: "remark",
    minWidth: 180,
    render: (row) => (row.remark ? frontEndStore.MASK_INFO(row.remark) : "-"),
  },
  {
    title: t("common.status"),
    key: "actions",
    width: 260,
    render: (row) => [
      h(
        NButton,
        {
          size: "small",
          secondary: true,
          loading: row.id ? validatingIds.value.has(row.id) : false,
          onClick: () => validateRowCredentials(row),
        },
        () => t("cert.action_verify"),
      ),
      h(
        NButton,
        {
          size: "small",
          secondary: true,
          style: "margin-left: 8px",
          onClick: () => {
            resetForm(row);
            showModal.value = true;
          },
        },
        () => t("common.edit"),
      ),
      h(
        NPopconfirm,
        { onPositiveClick: () => remove(row.id!) },
        {
          trigger: () =>
            h(
              NButton,
              {
                size: "small",
                type: "error",
                secondary: true,
                style: "margin-left: 8px",
              },
              () => t("common.delete"),
            ),
          default: () => t("common.confirm_delete"),
        },
      ),
    ],
  },
]);

onMounted(refresh);
</script>

<template>
  <n-flex vertical style="flex: 1">
    <n-flex justify="space-between">
      <n-button
        @click="
          resetForm();
          showModal = true;
        "
        >{{ t("common.create") }}</n-button
      >
      <n-button :loading="loading" @click="refresh">{{
        t("common.refresh")
      }}</n-button>
    </n-flex>

    <n-data-table :columns="columns" :data="items" :bordered="false" />

    <n-modal
      v-model:show="showModal"
      preset="card"
      style="width: 640px"
      :title="t('dns_provider.provider_profiles')"
    >
      <n-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-placement="left"
        label-width="auto"
      >
        <n-form-item :label="t('dns_provider.profile_name')" path="name">
          <n-input v-model:value="form.name" />
        </n-form-item>
        <n-form-item :label="t('dns_provider.provider')">
          <n-select
            :value="providerType"
            :options="providerOptions"
            @update:value="setProviderType"
          />
        </n-form-item>

        <template
          v-if="
            providerType === 'cloudflare' &&
            typeof form.provider_config === 'object' &&
            'cloudflare' in form.provider_config
          "
        >
          <n-form-item label="API Token"
            ><n-input
              v-model:value="form.provider_config.cloudflare.api_token"
              type="password"
              show-password-on="click"
          /></n-form-item>
        </template>
        <template
          v-else-if="
            providerType === 'aliyun' &&
            typeof form.provider_config === 'object' &&
            'aliyun' in form.provider_config
          "
        >
          <n-form-item label="Access Key ID"
            ><n-input v-model:value="form.provider_config.aliyun.access_key_id"
          /></n-form-item>
          <n-form-item label="Access Key Secret"
            ><n-input
              v-model:value="form.provider_config.aliyun.access_key_secret"
              type="password"
              show-password-on="click"
          /></n-form-item>
        </template>
        <template
          v-else-if="
            providerType === 'tencent' &&
            typeof form.provider_config === 'object' &&
            'tencent' in form.provider_config
          "
        >
          <n-form-item label="Secret ID"
            ><n-input v-model:value="form.provider_config.tencent.secret_id"
          /></n-form-item>
          <n-form-item label="Secret Key"
            ><n-input
              v-model:value="form.provider_config.tencent.secret_key"
              type="password"
              show-password-on="click"
          /></n-form-item>
        </template>
        <template
          v-else-if="
            providerType === 'aws' &&
            typeof form.provider_config === 'object' &&
            'aws' in form.provider_config
          "
        >
          <n-form-item label="Access Key ID"
            ><n-input v-model:value="form.provider_config.aws.access_key_id"
          /></n-form-item>
          <n-form-item label="Secret Access Key"
            ><n-input
              v-model:value="form.provider_config.aws.secret_access_key"
              type="password"
              show-password-on="click"
          /></n-form-item>
          <n-form-item label="Region"
            ><n-input v-model:value="form.provider_config.aws.region"
          /></n-form-item>
        </template>
        <template
          v-else-if="
            providerType === 'google' &&
            typeof form.provider_config === 'object' &&
            'google' in form.provider_config
          "
        >
          <n-form-item label="Service Account JSON"
            ><n-input
              v-model:value="form.provider_config.google.service_account_json"
              type="textarea"
              :autosize="{ minRows: 5, maxRows: 10 }"
          /></n-form-item>
        </template>

        <n-form-item :label="t('dns_provider.ddns_default_ttl')">
          <n-input-number
            v-model:value="form.ddns_default_ttl"
            :min="1"
            :precision="0"
            style="width: 100%"
          />
        </n-form-item>

        <n-alert type="info" :show-icon="false" style="margin-bottom: 12px">
          {{ t("dns_provider.ddns_default_ttl_hint") }}
        </n-alert>

        <n-form-item :label="t('common.remark')">
          <n-input
            v-model:value="form.remark"
            type="textarea"
            :autosize="{ minRows: 2, maxRows: 4 }"
          />
        </n-form-item>
      </n-form>

      <template #footer>
        <n-flex justify="space-between">
          <n-flex :size="8">
            <n-button
              secondary
              :loading="validating"
              :disabled="saving"
              @click="validateCredentials"
            >
              {{ t("cert.action_verify") }}
            </n-button>
            <n-button @click="showModal = false">{{
              t("common.cancel")
            }}</n-button>
          </n-flex>
          <n-button type="primary" :loading="saving" @click="save">{{
            t("common.save")
          }}</n-button>
        </n-flex>
      </template>
    </n-modal>
  </n-flex>
</template>
