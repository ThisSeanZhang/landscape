<script setup lang="ts">
import { computed, ref } from "vue";
import type {
  CertAccountConfig,
  CertConfig,
  CertType,
} from "@landscape-router/types/api/schemas";
import { get_cert, push_cert } from "@/api/cert/order";
import { get_cert_accounts } from "@/api/cert/account";
import { useI18n } from "vue-i18n";

type Props = {
  rule_id: string | null;
};

const props = defineProps<Props>();
const emit = defineEmits(["refresh"]);
const { t } = useI18n();

const show = defineModel<boolean>("show", { required: true });
const rule = ref<CertConfig>();
const origin_json = ref("");
const commit_spin = ref(false);
const formRef = ref();
const accounts = ref<CertAccountConfig[]>([]);

const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_json.value;
});

// --- Cert type helpers ---

const cert_type_kind = computed(() => {
  return rule.value?.cert_type?.t ?? "manual";
});

const is_acme = computed(() => cert_type_kind.value === "acme");

function on_cert_type_change(val: string) {
  if (!rule.value) return;
  if (val === "acme") {
    rule.value.cert_type = {
      t: "acme",
      account_id: accounts.value[0]?.id ?? "",
      challenge_type: {
        dns: { dns_provider: { cloudflare: { api_token: "" } } },
      } as unknown as CertType extends { t: "acme" } ? CertType : never,
      key_type: "ecdsa_p256",
      auto_renew: true,
      renew_before_days: 30,
    } as CertType;
  } else {
    rule.value.cert_type = { t: "manual" } as CertType;
    // Clear ACME-specific data
    rule.value.domains = [];
  }
}

// --- ACME field accessors ---

function getAcmeField<K extends string>(key: K): any {
  const ct = rule.value?.cert_type;
  if (ct && ct.t === "acme" && key in ct) {
    return (ct as any)[key];
  }
  return undefined;
}

function setAcmeField(key: string, val: any) {
  if (!rule.value?.cert_type || rule.value.cert_type.t !== "acme") return;
  (rule.value.cert_type as any)[key] = val;
}

const account_options = computed(() =>
  accounts.value.map((a) => ({
    label: a.name,
    value: a.id!,
  })),
);

const challenge_options = [{ label: "DNS-01", value: "dns" }];

const key_type_options = [
  { label: "ECDSA P-256", value: "ecdsa_p256" },
  { label: "ECDSA P-384", value: "ecdsa_p384" },
  { label: "RSA 2048", value: "rsa2048" },
  { label: "RSA 4096", value: "rsa4096" },
];

const dns_provider_options = [
  { label: t("cert.dns_provider_cloudflare"), value: "cloudflare" },
  // Temporarily disabled until backend support is ready:
  // { label: t("cert.dns_provider_aliyun"), value: "aliyun" },
  // { label: t("cert.dns_provider_tencent"), value: "tencent" },
  // { label: t("cert.dns_provider_aws"), value: "aws" },
  // { label: t("cert.dns_provider_google"), value: "google" },
  // { label: t("cert.dns_provider_custom"), value: "custom" },
];

const cert_type_options = [
  { label: t("cert.type_acme"), value: "acme" },
  { label: t("cert.type_manual"), value: "manual" },
];

// --- Externally tagged challenge_type helpers ---

function getChallengeKind(ct: any): "http" | "dns" {
  if (!ct || typeof ct !== "object") return "http";
  if ("http" in ct) return "http";
  if ("dns" in ct) return "dns";
  return "http";
}

const challengeKind = computed(() =>
  getChallengeKind(getAcmeField("challenge_type")),
);
const is_dns = computed(() => challengeKind.value === "dns");

function getHttpPort(ct: any): number {
  if (ct && typeof ct === "object" && "http" in ct && ct.http) {
    return (ct.http as { port?: number }).port ?? 80;
  }
  return 80;
}

const httpPort = computed({
  get() {
    return getHttpPort(getAcmeField("challenge_type"));
  },
  set(val: number) {
    setAcmeField("challenge_type", { http: { port: val } });
  },
});

// --- Externally tagged dns_provider helpers ---

function getDnsProviderKey(ct: any): string {
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

function getDnsProviderFields(ct: any): Record<string, string> {
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
  getDnsProviderKey(getAcmeField("challenge_type")),
);

function setDnsProvider(key: string, fields: Record<string, string>) {
  let dp: unknown;
  if (key === "manual") {
    dp = "manual";
  } else {
    dp = { [key]: fields };
  }
  setAcmeField("challenge_type", { dns: { dns_provider: dp } });
}

// Computed getters/setters for DNS provider fields
function dnsField(fieldName: string): string {
  return getDnsProviderFields(getAcmeField("challenge_type"))[fieldName] ?? "";
}

function setDnsField(fieldName: string, val: string) {
  const fields = { ...getDnsProviderFields(getAcmeField("challenge_type")) };
  fields[fieldName] = val;
  setDnsProvider(dnsProviderKey.value, fields);
}

async function enter() {
  accounts.value = await get_cert_accounts();
  if (props.rule_id) {
    rule.value = await get_cert(props.rule_id);
  } else {
    rule.value = {
      name: "",
      domains: [],
      status: "pending",
      for_api: false,
      for_gateway: false,
      cert_type: {
        t: "acme",
        account_id: accounts.value[0]?.id ?? "",
        challenge_type: {
          dns: { dns_provider: { cloudflare: { api_token: "" } } },
        },
        key_type: "ecdsa_p256",
        auto_renew: true,
        renew_before_days: 30,
      } as CertType,
    };
  }
  // Keep UI consistent with currently supported challenge/provider combinations.
  if (rule.value?.cert_type?.t === "acme") {
    const challenge = getChallengeKind(getAcmeField("challenge_type"));
    if (challenge !== "dns") {
      setAcmeField("challenge_type", {
        dns: { dns_provider: { cloudflare: { api_token: "" } } },
      });
    }
    const provider = getDnsProviderKey(getAcmeField("challenge_type"));
    if (provider !== "cloudflare") {
      setDnsProvider("cloudflare", { api_token: "" });
    }
  }
  origin_json.value = JSON.stringify(rule.value);
}

function on_challenge_change(val: string) {
  if (val === "dns") {
    setAcmeField("challenge_type", {
      dns: { dns_provider: { cloudflare: { api_token: "" } } },
    });
  } else {
    setAcmeField("challenge_type", { http: { port: 80 } });
  }
}

function on_dns_provider_change(val: string) {
  switch (val) {
    case "cloudflare":
      setDnsProvider("cloudflare", { api_token: "" });
      break;
    // Temporarily disabled until backend support is ready:
    // case "aliyun":
    //   setDnsProvider("aliyun", { access_key_id: "", access_key_secret: "" });
    //   break;
    // case "tencent":
    //   setDnsProvider("tencent", { secret_id: "", secret_key: "" });
    //   break;
    // case "aws":
    //   setDnsProvider("aws", {
    //     access_key_id: "",
    //     secret_access_key: "",
    //     region: "",
    //   });
    //   break;
    // case "google":
    //   setDnsProvider("google", { service_account_json: "" });
    //   break;
    // case "custom":
    //   setDnsProvider("custom", { script_path: "" });
    //   break;
    default:
      setDnsProvider("cloudflare", { api_token: "" });
  }
}

const domain_rule = {
  trigger: ["input", "blur"],
  validator(_: unknown, value: string) {
    if (!value) return new Error(t("cert.cert_domains_required"));
    if (
      !/^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(
        value,
      )
    )
      return new Error(t("cert.cert_domain_invalid"));
    return true;
  },
};

const rules = {
  name: {
    required: true,
    trigger: ["input", "blur"],
    message: () => t("cert.cert_name_required"),
  },
  domains: {
    trigger: ["change"],
    validator(_: unknown, value: string[]) {
      if (is_acme.value && (!value || value.length === 0))
        return new Error(t("cert.cert_domains_required"));
      return true;
    },
  },
};

async function save() {
  if (!rule.value) return;
  try {
    await formRef.value?.validate();
    commit_spin.value = true;
    await push_cert(rule.value);
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
    :title="t('cert.cert_edit_title')"
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
      <n-form-item :label="t('cert.cert_type')">
        <n-select
          :value="cert_type_kind"
          :options="cert_type_options"
          @update:value="on_cert_type_change"
        />
      </n-form-item>

      <n-form-item :label="t('cert.cert_name')" path="name">
        <n-input v-model:value="rule.name" />
      </n-form-item>

      <n-form-item :label="t('cert.for_api')">
        <n-switch v-model:value="rule.for_api">
          <template #checked>{{ t("common.enable") }}</template>
          <template #unchecked>{{ t("common.disable") }}</template>
        </n-switch>
      </n-form-item>

      <n-form-item :label="t('cert.for_gateway')">
        <n-switch v-model:value="rule.for_gateway">
          <template #checked>{{ t("common.enable") }}</template>
          <template #unchecked>{{ t("common.disable") }}</template>
        </n-switch>
      </n-form-item>

      <!-- ===== ACME mode ===== -->
      <template v-if="is_acme && rule.cert_type && rule.cert_type.t === 'acme'">
        <n-form-item :label="t('cert.acme_account')">
          <n-select
            :value="rule.cert_type.account_id"
            @update:value="(v: string) => setAcmeField('account_id', v)"
            :options="account_options"
            :placeholder="t('cert.acme_account_required')"
          />
        </n-form-item>

        <n-form-item :label="t('cert.cert_domains')" path="domains">
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

        <n-form-item :label="t('cert.acme_key_type')">
          <n-select
            :value="rule.cert_type.key_type"
            @update:value="(v: string) => setAcmeField('key_type', v)"
            :options="key_type_options"
          />
        </n-form-item>

        <n-form-item :label="t('cert.acme_challenge')">
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

          <!-- Temporarily disabled until backend support is ready:
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
                @update:value="
                  (v: string) => setDnsField('access_key_secret', v)
                "
                type="password"
                show-password-on="click"
              />
            </n-form-item>
          </template>
          -->

          <!-- Temporarily disabled until backend support is ready:
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
          -->

          <!-- Temporarily disabled until backend support is ready:
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
                @update:value="
                  (v: string) => setDnsField('secret_access_key', v)
                "
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
          -->

          <!-- Temporarily disabled until backend support is ready:
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
          -->

          <!-- Temporarily disabled until backend support is ready:
          <template v-if="dnsProviderKey === 'custom'">
            <n-form-item label="Script Path">
              <n-input
                :value="dnsField('script_path')"
                @update:value="(v: string) => setDnsField('script_path', v)"
                placeholder="/path/to/script.sh"
              />
            </n-form-item>
          </template>
          -->
        </template>

        <n-form-item :label="t('cert.acme_auto_renew')">
          <n-switch
            :value="rule.cert_type.auto_renew"
            @update:value="(v: boolean) => setAcmeField('auto_renew', v)"
          >
            <template #checked>{{ t("common.enable") }}</template>
            <template #unchecked>{{ t("common.disable") }}</template>
          </n-switch>
        </n-form-item>

        <n-form-item
          v-if="rule.cert_type.auto_renew"
          :label="t('cert.acme_renew_before_days')"
        >
          <n-input-number
            :value="rule.cert_type.renew_before_days"
            @update:value="(v: number) => setAcmeField('renew_before_days', v)"
            :min="1"
            :max="90"
          />
        </n-form-item>
      </template>

      <!-- ===== Manual mode ===== -->
      <template v-if="!is_acme">
        <n-form-item :label="t('cert.upload_cert')">
          <n-input
            v-model:value="rule.certificate"
            type="textarea"
            :rows="5"
            placeholder="-----BEGIN CERTIFICATE-----"
          />
        </n-form-item>

        <n-form-item :label="t('cert.upload_key')">
          <n-input
            v-model:value="rule.private_key"
            type="textarea"
            :rows="5"
            placeholder="-----BEGIN PRIVATE KEY-----"
          />
        </n-form-item>

        <n-form-item :label="t('cert.upload_chain')">
          <n-input
            v-model:value="rule.certificate_chain"
            type="textarea"
            :rows="3"
            placeholder="-----BEGIN CERTIFICATE-----"
          />
        </n-form-item>
      </template>
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
