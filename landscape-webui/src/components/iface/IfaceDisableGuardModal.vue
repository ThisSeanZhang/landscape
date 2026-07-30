<script setup lang="ts">
import { ref, computed } from "vue";
import { useI18n } from "vue-i18n";
import {
  get_iface_disable_risk_caller,
  type IfaceDisableRiskCaller,
} from "@/lib/iface_disable_guard";

const props = withDefaults(
  defineProps<{
    iface_name: string;
    title?: string;
    warning?: string;
    confirm_button_text?: string;
  }>(),
  {
    title: "",
    warning: "",
    confirm_button_text: "",
  },
);

const emit = defineEmits<{
  (e: "refresh"): void;
}>();

const { t } = useI18n();
const show = ref(false);
const caller = ref<IfaceDisableRiskCaller | null>(null);
const input_value = ref("");
const loading = ref(false);
const pending_action = ref<(() => Promise<void>) | null>(null);

const is_match = computed(() => {
  return input_value.value === props.iface_name;
});

const display_title = computed(
  () => props.title || t("network.iface_risk_guard.title"),
);
const display_warning = computed(
  () => props.warning || t("network.iface_risk_guard.warning"),
);
const display_confirm_button_text = computed(
  () =>
    props.confirm_button_text || t("network.iface_risk_guard.confirm_button"),
);

async function check_and_execute(action: () => Promise<void>) {
  loading.value = true;
  try {
    const caller_info = await get_iface_disable_risk_caller(props.iface_name);
    if (!caller_info) {
      // No risk, execute immediately
      await action();
    } else {
      // Risk detected, show modal
      caller.value = caller_info;
      pending_action.value = action;
      input_value.value = "";
      show.value = true;
    }
  } finally {
    loading.value = false;
  }
}

async function handle_confirm() {
  if (!pending_action.value) return;
  loading.value = true;
  try {
    await pending_action.value();
    show.value = false;
    pending_action.value = null;
  } finally {
    loading.value = false;
  }
}

defineExpose({
  check_and_execute,
});
</script>

<template>
  <n-modal
    v-model:show="show"
    preset="dialog"
    type="warning"
    :title="display_title"
  >
    <template #default>
      <n-flex vertical size="small">
        <n-alert type="warning" :show-icon="false">
          {{ display_warning }}
        </n-alert>
        <n-text>{{
          t("network.iface_risk_guard.current_iface", {
            iface: caller?.iface_name,
          })
        }}</n-text>
        <n-text>{{
          t("network.iface_risk_guard.current_ip", { ip: caller?.ip })
        }}</n-text>
        <n-text>{{
          t("network.iface_risk_guard.current_source", {
            source: caller?.source,
          })
        }}</n-text>
        <n-text v-if="caller?.hostname">{{
          t("network.iface_risk_guard.current_hostname", {
            hostname: caller?.hostname,
          })
        }}</n-text>

        <n-text style="margin-top: 8px">{{
          t("network.iface_risk_guard.input_label", {
            iface: caller?.iface_name,
          })
        }}</n-text>
        <n-input
          v-model:value="input_value"
          :placeholder="
            t('network.iface_risk_guard.input_placeholder', {
              iface: caller?.iface_name,
            })
          "
        />
        <n-text depth="3" style="font-size: 12px">{{
          t("network.iface_risk_guard.input_hint")
        }}</n-text>
      </n-flex>
    </template>

    <template #action>
      <n-flex justify="end">
        <n-button @click="show = false">{{ t("common.cancel") }}</n-button>
        <n-button
          type="error"
          :disabled="!is_match"
          :loading="loading"
          @click="handle_confirm"
        >
          {{ display_confirm_button_text }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
