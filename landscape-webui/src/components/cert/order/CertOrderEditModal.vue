<script setup lang="ts">
import { computed, ref } from "vue";
import type {
  CertAccountConfig,
  CertOrderConfig,
} from "@landscape-router/types/api/schemas";
import { get_cert_order, push_cert_order } from "@/api/cert/order";
import { get_cert_accounts } from "@/api/cert/account";
import { useI18n } from "vue-i18n";

type Props = {
  rule_id: string | null;
};

const props = defineProps<Props>();
const emit = defineEmits(["refresh"]);
const { t } = useI18n();

const show = defineModel<boolean>("show", { required: true });
const rule = ref<CertOrderConfig>();
const origin_json = ref("");
const commit_spin = ref(false);
const formRef = ref();
const accounts = ref<CertAccountConfig[]>([]);

const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_json.value;
});

const account_options = computed(() =>
  accounts.value.map((a) => ({
    label: a.name,
    value: a.id!,
  })),
);

const challenge_options = [
  { label: "HTTP-01", value: "http" },
  { label: "DNS-01", value: "dns" },
];

const key_type_options = [
  { label: "ECDSA P-256", value: "ecdsa_p256" },
  { label: "ECDSA P-384", value: "ecdsa_p384" },
  { label: "RSA 2048", value: "rsa2048" },
  { label: "RSA 4096", value: "rsa4096" },
];

const dns_provider_options = [
  { label: t("cert.dns_provider_manual"), value: "manual" },
  { label: t("cert.dns_provider_cloudflare"), value: "cloudflare" },
  { label: t("cert.dns_provider_aliyun"), value: "aliyun" },
  { label: t("cert.dns_provider_tencent"), value: "tencent" },
  { label: t("cert.dns_provider_aws"), value: "aws" },
  { label: t("cert.dns_provider_google"), value: "google" },
  { label: t("cert.dns_provider_custom"), value: "custom" },
];

// --- Externally tagged challenge_type helpers ---

function getChallengeKind(
  ct: CertOrderConfig["challenge_type"],
): "http" | "dns" {
  if (!ct || typeof ct !== "object") return "http";
  if ("http" in ct) return "http";
  if ("dns" in ct) return "dns";
  return "http";
}

const challengeKind = computed(() =>
  getChallengeKind(rule.value?.challenge_type),
);
const is_dns = computed(() => challengeKind.value === "dns");

function getHttpPort(ct: CertOrderConfig["challenge_type"]): number {
  if (ct && typeof ct === "object" && "http" in ct && ct.http) {
    return (ct.http as { port?: number }).port ?? 80;
  }
  return 80;
}

const httpPort = computed({
  get() {
    return getHttpPort(rule.value?.challenge_type);
  },
  set(val: number) {
    if (!rule.value) return;
    rule.value.challenge_type = {
      http: { port: val },
    } as unknown as CertOrderConfig["challenge_type"];
  },
});

// --- Externally tagged dns_provider helpers ---

function getDnsProviderKey(ct: CertOrderConfig["challenge_type"]): string {
  if (!ct || typeof ct !== "object" || !("dns" in ct)) return "manual";
  const dns = (ct as { dns: { dns_provider?: unknown } }).dns;
  if (!dns?.dns_provider) return "manual";
  const dp = dns.dns_provider;
  if (typeof dp === "string") return dp;
  if (typeof dp === "object" && dp !== null) {
    const keys = Object.keys(dp);
    return keys.length > 0 ? keys[0] : "manual";
  }
  return "manual";
}

function getDnsProviderFields(
  ct: CertOrderConfig["challenge_type"],
): Record<string, string> {
  if (!ct || typeof ct !== "object" || !("dns" in ct)) return {};
  const dns = (ct as { dns: { dns_provider?: unknown } }).dns;
  if (!dns?.dns_provider) return {};
  const dp = dns.dns_provider;
  if (typeof dp === "string") return {};
  if (typeof dp === "object" && dp !== null) {
    const keys = Object.keys(dp);
    if (keys.length > 0) {
      return (dp as Record<string, Record<string, string>>)[keys[0]] ?? {};
    }
  }
  return {};
}

const dnsProviderKey = computed(() =>
  getDnsProviderKey(rule.value?.challenge_type),
);

function setDnsProvider(key: string, fields: Record<string, string>) {
  if (!rule.value) return;
  let dp: unknown;
  if (key === "manual") {
    dp = "manual";
  } else {
    dp = { [key]: fields };
  }
  rule.value.challenge_type = {
    dns: { dns_provider: dp },
  } as unknown as CertOrderConfig["challenge_type"];
}

// Computed getters/setters for DNS provider fields
function dnsField(fieldName: string): string {
  return getDnsProviderFields(rule.value?.challenge_type)[fieldName] ?? "";
}

function setDnsField(fieldName: string, val: string) {
  const fields = { ...getDnsProviderFields(rule.value?.challenge_type) };
  fields[fieldName] = val;
  setDnsProvider(dnsProviderKey.value, fields);
}

async function enter() {
  accounts.value = await get_cert_accounts();
  if (props.rule_id) {
    rule.value = await get_cert_order(props.rule_id);
  } else {
    rule.value = {
      name: "",
      account_id: accounts.value[0]?.id ?? "",
      domains: [],
      challenge_type: {
        http: { port: 80 },
      } as unknown as CertOrderConfig["challenge_type"],
      key_type: "ecdsa_p256",
      status: "pending",
      auto_renew: true,
      renew_before_days: 30,
    };
  }
  origin_json.value = JSON.stringify(rule.value);
}

function on_challenge_change(val: string) {
  if (!rule.value) return;
  if (val === "dns") {
    rule.value.challenge_type = {
      dns: { dns_provider: "manual" },
    } as unknown as CertOrderConfig["challenge_type"];
  } else {
    rule.value.challenge_type = {
      http: { port: 80 },
    } as unknown as CertOrderConfig["challenge_type"];
  }
}

function on_dns_provider_change(val: string) {
  if (!rule.value) return;
  switch (val) {
    case "cloudflare":
      setDnsProvider("cloudflare", { api_token: "" });
      break;
    case "aliyun":
      setDnsProvider("aliyun", { access_key_id: "", access_key_secret: "" });
      break;
    case "tencent":
      setDnsProvider("tencent", { secret_id: "", secret_key: "" });
      break;
    case "aws":
      setDnsProvider("aws", {
        access_key_id: "",
        secret_access_key: "",
        region: "",
      });
      break;
    case "google":
      setDnsProvider("google", { service_account_json: "" });
      break;
    case "custom":
      setDnsProvider("custom", { script_path: "" });
      break;
    default:
      setDnsProvider("manual", {});
  }
}

const domain_rule = {
  trigger: ["input", "blur"],
  validator(_: unknown, value: string) {
    if (!value) return new Error(t("cert.order_domains_required"));
    if (
      !/^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(
        value,
      )
    )
      return new Error(t("cert.order_domain_invalid"));
    return true;
  },
};

const rules = {
  name: {
    required: true,
    trigger: ["input", "blur"],
    message: () => t("cert.order_name_required"),
  },
  account_id: {
    required: true,
    trigger: ["change", "blur"],
    message: () => t("cert.order_account_required"),
  },
  domains: {
    trigger: ["change"],
    validator(_: unknown, value: string[]) {
      if (!value || value.length === 0)
        return new Error(t("cert.order_domains_required"));
      return true;
    },
  },
};

async function save() {
  if (!rule.value) return;
  try {
    await formRef.value?.validate();
    commit_spin.value = true;
    await push_cert_order(rule.value);
    show.value = false;
    emit("refresh");
  } finally {
    commit_spin.value = false;
  }
}
</script>

<template>
  <n-modal
    :auto-focus="false"
    v-model:show="show"
    style="width: 600px"
    class="custom-card"
    preset="card"
    :title="t('cert.order_edit_title')"
    @after-enter="enter"
    :bordered="false"
  >
    <n-form
      v-if="rule"
      :rules="rules"
      ref="formRef"
      :model="rule"
      label-placement="left"
      label-width="auto"
    >
      <n-form-item :label="t('cert.order_name')" path="name">
        <n-input v-model:value="rule.name" />
      </n-form-item>

      <n-form-item :label="t('cert.order_account')" path="account_id">
        <n-select
          v-model:value="rule.account_id"
          :options="account_options"
          :placeholder="t('cert.order_account_required')"
        />
      </n-form-item>

      <n-form-item :label="t('cert.order_domains')" path="domains">
        <n-dynamic-input
          v-model:value="rule.domains"
          placeholder="example.com"
          #="{ index }"
        >
          <n-form-item
            :path="`domains[${index}]`"
            :rule="domain_rule"
            ignore-path-change
            :show-label="false"
            :show-feedback="false"
            style="margin-bottom: 0; flex: 1"
          >
            <n-input
              v-model:value="rule.domains[index]"
              placeholder="example.com"
              @keydown.enter.prevent
            />
          </n-form-item>
        </n-dynamic-input>
      </n-form-item>

      <n-form-item :label="t('cert.order_key_type')">
        <n-select v-model:value="rule.key_type" :options="key_type_options" />
      </n-form-item>

      <n-form-item :label="t('cert.order_challenge')">
        <n-select
          :value="challengeKind"
          :options="challenge_options"
          @update:value="on_challenge_change"
        />
      </n-form-item>

      <template v-if="!is_dns">
        <n-form-item :label="t('cert.http_challenge_port')">
          <n-input-number v-model:value="httpPort" :min="1" :max="65535" />
        </n-form-item>
      </template>

      <template v-if="is_dns">
        <n-form-item :label="t('cert.dns_provider')">
          <n-select
            :value="dnsProviderKey"
            :options="dns_provider_options"
            @update:value="on_dns_provider_change"
          />
        </n-form-item>

        <!-- Cloudflare -->
        <template v-if="dnsProviderKey === 'cloudflare'">
          <n-form-item label="API Token">
            <n-input
              :value="dnsField('api_token')"
              @update:value="(v: string) => setDnsField('api_token', v)"
              type="password"
              show-password-on="click"
            />
          </n-form-item>
        </template>

        <!-- Aliyun -->
        <template v-if="dnsProviderKey === 'aliyun'">
          <n-form-item label="Access Key ID">
            <n-input
              :value="dnsField('access_key_id')"
              @update:value="(v: string) => setDnsField('access_key_id', v)"
            />
          </n-form-item>
          <n-form-item label="Access Key Secret">
            <n-input
              :value="dnsField('access_key_secret')"
              @update:value="(v: string) => setDnsField('access_key_secret', v)"
              type="password"
              show-password-on="click"
            />
          </n-form-item>
        </template>

        <!-- Tencent -->
        <template v-if="dnsProviderKey === 'tencent'">
          <n-form-item label="Secret ID">
            <n-input
              :value="dnsField('secret_id')"
              @update:value="(v: string) => setDnsField('secret_id', v)"
            />
          </n-form-item>
          <n-form-item label="Secret Key">
            <n-input
              :value="dnsField('secret_key')"
              @update:value="(v: string) => setDnsField('secret_key', v)"
              type="password"
              show-password-on="click"
            />
          </n-form-item>
        </template>

        <!-- AWS -->
        <template v-if="dnsProviderKey === 'aws'">
          <n-form-item label="Access Key ID">
            <n-input
              :value="dnsField('access_key_id')"
              @update:value="(v: string) => setDnsField('access_key_id', v)"
            />
          </n-form-item>
          <n-form-item label="Secret Access Key">
            <n-input
              :value="dnsField('secret_access_key')"
              @update:value="(v: string) => setDnsField('secret_access_key', v)"
              type="password"
              show-password-on="click"
            />
          </n-form-item>
          <n-form-item label="Region">
            <n-input
              :value="dnsField('region')"
              @update:value="(v: string) => setDnsField('region', v)"
              placeholder="us-east-1"
            />
          </n-form-item>
        </template>

        <!-- Google -->
        <template v-if="dnsProviderKey === 'google'">
          <n-form-item label="Service Account JSON">
            <n-input
              :value="dnsField('service_account_json')"
              @update:value="
                (v: string) => setDnsField('service_account_json', v)
              "
              type="textarea"
              :rows="3"
            />
          </n-form-item>
        </template>

        <!-- Custom -->
        <template v-if="dnsProviderKey === 'custom'">
          <n-form-item label="Script Path">
            <n-input
              :value="dnsField('script_path')"
              @update:value="(v: string) => setDnsField('script_path', v)"
              placeholder="/path/to/script.sh"
            />
          </n-form-item>
        </template>
      </template>

      <n-form-item :label="t('cert.order_auto_renew')">
        <n-switch v-model:value="rule.auto_renew">
          <template #checked>{{ t("common.enable") }}</template>
          <template #unchecked>{{ t("common.disable") }}</template>
        </n-switch>
      </n-form-item>

      <n-form-item
        v-if="rule.auto_renew"
        :label="t('cert.order_renew_before_days')"
      >
        <n-input-number
          v-model:value="rule.renew_before_days"
          :min="1"
          :max="90"
        />
      </n-form-item>
    </n-form>

    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{ t("common.cancel") }}</n-button>
        <n-button :loading="commit_spin" @click="save" :disabled="!isModified">
          {{ t("common.save") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
