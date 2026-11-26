<script setup lang="ts">
import { ref } from "vue";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";
import { change_password } from "@/api/auth";
import { useRouter } from "vue-router";
import { LANDSCAPE_TOKEN_KEY } from "@/lib/common";

const { t } = useI18n();
const message = useMessage();
const router = useRouter();
const loading = ref(false);

const form = ref({
  current_password: "",
  new_password: "",
  confirm_password: "",
});

function validatePassword(pwd: string): string | null {
  if (pwd.length < 8) return t("config.password_min_length");
  if (!/[a-z]/.test(pwd)) return t("config.password_need_lowercase");
  if (!/[A-Z]/.test(pwd)) return t("config.password_need_uppercase");
  if (!/[0-9]/.test(pwd)) return t("config.password_need_digit");
  return null;
}

async function handleSubmit() {
  if (!form.value.current_password) {
    message.warning(t("config.current_password_required"));
    return;
  }
  const pwdError = validatePassword(form.value.new_password);
  if (pwdError) {
    message.warning(pwdError);
    return;
  }
  if (form.value.new_password !== form.value.confirm_password) {
    message.warning(t("config.password_mismatch"));
    return;
  }
  if (form.value.new_password === form.value.current_password) {
    message.warning(t("config.password_same_as_old"));
    return;
  }

  loading.value = true;
  try {
    await change_password(form.value);
    message.success(t("config.password_change_success"));
    form.value = {
      current_password: "",
      new_password: "",
      confirm_password: "",
    };
    // Force re-login
    localStorage.removeItem(LANDSCAPE_TOKEN_KEY);
    router.push("/login");
  } catch (e: any) {
    // Error toast handled by axios interceptor for API errors
    if (!e?.response) {
      message.error(t("config.save_failed"));
    }
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <n-card :title="t('config.password_title')" segmented id="password-config">
    <n-form label-placement="left" label-width="140">
      <n-form-item :label="t('config.current_password')">
        <n-input
          type="password"
          show-password-on="click"
          v-model:value="form.current_password"
          :placeholder="t('config.current_password_placeholder')"
        />
      </n-form-item>
      <n-form-item :label="t('config.new_password')">
        <n-input
          type="password"
          show-password-on="click"
          v-model:value="form.new_password"
          :placeholder="t('config.new_password_placeholder')"
        />
      </n-form-item>
      <n-form-item :label="t('config.confirm_password')">
        <n-input
          type="password"
          show-password-on="click"
          v-model:value="form.confirm_password"
          :placeholder="t('config.confirm_password_placeholder')"
          @keyup.enter="handleSubmit"
        />
      </n-form-item>
    </n-form>
    <n-button type="warning" :loading="loading" @click="handleSubmit">
      {{ t("config.change_password") }}
    </n-button>
  </n-card>
</template>
