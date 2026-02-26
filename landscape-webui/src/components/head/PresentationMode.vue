<script setup lang="ts">
import { useFrontEndStore } from "@/stores/front_end_config";
import { IosEye, IosEyeOff } from "@vicons/ionicons4";
import { useI18n } from "vue-i18n";

const frontEndStore = useFrontEndStore();
const { t } = useI18n();
</script>
<template>
  <n-popover trigger="hover">
    <template #trigger>
      <n-button
        v-if="frontEndStore.presentation_mode"
        text
        style="font-size: 24px"
        @click="
          frontEndStore.presentation_mode = !frontEndStore.presentation_mode
        "
      >
        <n-icon>
          <IosEyeOff />
        </n-icon>
      </n-button>
      <n-button
        v-else
        text
        style="font-size: 24px"
        @click="
          frontEndStore.presentation_mode = !frontEndStore.presentation_mode
        "
      >
        <n-icon>
          <IosEye />
        </n-icon>
      </n-button>
    </template>
    <span>
      {{ t("common.switch_current") }}
      <n-button
        style="cursor: default; pointer-events: none"
        @click.stop="() => {}"
        text
        target="_blank"
        type="primary"
      >
        {{ t("common.privacy_mode") }}
      </n-button>
      <br />
      {{ t("common.privacy_mode_desc") }}
    </span>
  </n-popover>
</template>
