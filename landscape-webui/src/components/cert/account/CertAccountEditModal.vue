<script setup lang="ts">
import { computed, ref } from "vue";
import type { CertAccountConfig } from "@landscape-router/types/api/schemas";
import { get_cert_account, push_cert_account } from "@/api/cert/account";
import { useI18n } from "vue-i18n";

type Props = {
  rule_id: string | null;
};

const props = defineProps<Props>();
const emit = defineEmits(["refresh"]);
const { t } = useI18n();

const show = defineModel<boolean>("show", { required: true });
const rule = ref<CertAccountConfig>();
const origin_json = ref("");
const commit_spin = ref(false);
const formRef = ref();

const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_json.value;
});

function getProviderType(config: CertAccountConfig["provider_config"]): string {
  if (typeof config === "string") return config;
  if (config && typeof config === "object") {
    const keys = Object.keys(config);
    if (keys.length > 0) return keys[0];
  }
  return "lets_encrypt";
}

const providerType = computed(() => {
  if (!rule.value) return "lets_encrypt";
  return getProviderType(rule.value.provider_config);
});

const is_zerossl = computed(() => providerType.value === "zero_ssl");

const provider_options = [
  { label: "Let's Encrypt", value: "lets_encrypt" },
  { label: "ZeroSSL", value: "zero_ssl" },
];

function getZeroSslFields(config: CertAccountConfig["provider_config"]): {
  eab_kid: string;
  eab_hmac_key: string;
} {
  if (
    config &&
    typeof config === "object" &&
    "zero_ssl" in config &&
    config.zero_ssl
  ) {
    const z = config.zero_ssl as { eab_kid?: string; eab_hmac_key?: string };
    return { eab_kid: z.eab_kid ?? "", eab_hmac_key: z.eab_hmac_key ?? "" };
  }
  return { eab_kid: "", eab_hmac_key: "" };
}

const zeroSslEabKid = computed({
  get() {
    return getZeroSslFields(rule.value?.provider_config).eab_kid;
  },
  set(val: string) {
    if (!rule.value) return;
    const fields = getZeroSslFields(rule.value.provider_config);
    rule.value.provider_config = {
      zero_ssl: { eab_kid: val, eab_hmac_key: fields.eab_hmac_key },
    } as unknown as CertAccountConfig["provider_config"];
  },
});

const zeroSslEabHmacKey = computed({
  get() {
    return getZeroSslFields(rule.value?.provider_config).eab_hmac_key;
  },
  set(val: string) {
    if (!rule.value) return;
    const fields = getZeroSslFields(rule.value.provider_config);
    rule.value.provider_config = {
      zero_ssl: { eab_kid: fields.eab_kid, eab_hmac_key: val },
    } as unknown as CertAccountConfig["provider_config"];
  },
});

async function enter() {
  if (props.rule_id) {
    rule.value = await get_cert_account(props.rule_id);
  } else {
    rule.value = {
      name: "",
      email: "",
      provider_config:
        "lets_encrypt" as unknown as CertAccountConfig["provider_config"],
      use_staging: false,
      terms_agreed: true,
      status: "unregistered",
    };
  }
  origin_json.value = JSON.stringify(rule.value);
}

function on_provider_change(val: string) {
  if (!rule.value) return;
  if (val === "zero_ssl") {
    rule.value.provider_config = {
      zero_ssl: { eab_kid: "", eab_hmac_key: "" },
    } as unknown as CertAccountConfig["provider_config"];
    rule.value.use_staging = false;
  } else {
    rule.value.provider_config =
      "lets_encrypt" as unknown as CertAccountConfig["provider_config"];
  }
}

const rules = {
  name: {
    required: true,
    trigger: ["input", "blur"],
    message: () => t("cert.account_name_required"),
  },
  email: {
    required: true,
    trigger: ["input", "blur"],
    validator(_: unknown, value: string) {
      if (!value) return new Error(t("cert.account_email_required"));
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))
        return new Error(t("cert.account_email_invalid"));
      return true;
    },
  },
};

async function save() {
  if (!rule.value) return;
  try {
    await formRef.value?.validate();
    commit_spin.value = true;
    await push_cert_account(rule.value);
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
    style="width: 550px"
    class="custom-card"
    preset="card"
    :title="t('cert.account_edit_title')"
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
      <n-form-item :label="t('cert.account_name')" path="name">
        <n-input v-model:value="rule.name" />
      </n-form-item>

      <n-form-item :label="t('cert.account_email')" path="email">
        <n-input v-model:value="rule.email" />
      </n-form-item>

      <n-form-item :label="t('cert.account_provider')">
        <n-select
          :value="providerType"
          :options="provider_options"
          @update:value="on_provider_change"
        />
      </n-form-item>

      <template v-if="is_zerossl">
        <n-form-item :label="t('cert.account_eab_kid')">
          <n-input v-model:value="zeroSslEabKid" />
        </n-form-item>
        <n-form-item :label="t('cert.account_eab_hmac')">
          <n-input v-model:value="zeroSslEabHmacKey" show-password-on="click" />
        </n-form-item>
      </template>

      <n-form-item :label="t('cert.account_staging')">
        <n-switch v-model:value="rule.use_staging" :disabled="is_zerossl">
          <template #checked>{{ t("common.enable") }}</template>
          <template #unchecked>{{ t("common.disable") }}</template>
        </n-switch>
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
