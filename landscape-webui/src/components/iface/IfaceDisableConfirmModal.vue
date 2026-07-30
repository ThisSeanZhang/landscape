<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";

import type { CallerIdentityResponse } from "@landscape-router/types/api/schemas";

const props = defineProps<{
  show: boolean;
  ifaceName: string;
  callerInfo: CallerIdentityResponse | null;
  loading?: boolean;
}>();

const emit = defineEmits<{
  (e: "update:show", value: boolean): void;
  (e: "confirm"): void;
}>();

const { t } = useI18n();
const confirmText = ref("");

const inputMatched = computed(() => confirmText.value === props.ifaceName);

watch(
  () => props.show,
  (show) => {
    if (!show) {
      confirmText.value = "";
    }
  },
);

function handleClose() {
  emit("update:show", false);
}

function handleConfirm() {
  if (!inputMatched.value) {
    return;
  }

  emit("confirm");
}
</script>

<template>
  <n-modal
    :show="show"
    preset="card"
    style="width: min(92vw, 560px)"
    :title="t('network.iface_risk_guard.title')"
    :mask-closable="!loading"
    :closable="!loading"
    @update:show="emit('update:show', $event)"
  >
    <n-flex vertical :size="14">
      <n-alert type="warning" :show-icon="true">
        {{ t("network.iface_risk_guard.warning") }}
      </n-alert>

      <n-flex vertical :size="6">
        <n-text>
          {{
            t("network.iface_risk_guard.current_iface", { iface: ifaceName })
          }}
        </n-text>
        <n-text v-if="callerInfo?.ip" depth="3">
          {{ t("network.iface_risk_guard.current_ip", { ip: callerInfo.ip }) }}
        </n-text>
        <n-text v-if="callerInfo?.source" depth="3">
          {{
            t("network.iface_risk_guard.current_source", {
              source: callerInfo.source,
            })
          }}
        </n-text>
        <n-text v-if="callerInfo?.hostname" depth="3">
          {{
            t("network.iface_risk_guard.current_hostname", {
              hostname: callerInfo.hostname,
            })
          }}
        </n-text>
      </n-flex>

      <n-text>
        {{ t("network.iface_risk_guard.input_label", { iface: ifaceName }) }}
      </n-text>
      <n-input
        v-model:value="confirmText"
        :placeholder="
          t('network.iface_risk_guard.input_placeholder', { iface: ifaceName })
        "
        :disabled="loading"
      />
      <n-text depth="3">
        {{ t("network.iface_risk_guard.input_hint") }}
      </n-text>
    </n-flex>

    <template #footer>
      <n-flex justify="end">
        <n-button :disabled="loading" @click="handleClose">
          {{ t("common.cancel") }}
        </n-button>
        <n-button
          type="error"
          :loading="loading"
          :disabled="!inputMatched"
          @click="handleConfirm"
        >
          {{ t("network.iface_risk_guard.confirm_button") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
