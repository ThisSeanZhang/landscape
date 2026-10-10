<script lang="ts" setup>
import { HelpFilled } from "@vicons/carbon";
import { computed } from "vue";
import { useThemeVars } from "naive-ui";

const props = withDefaults(defineProps<{ warn?: boolean }>(), { warn: false });

const themeVars = useThemeVars();
const iconColor = computed(() =>
  props.warn ? themeVars.value.warningColor : undefined,
);
</script>
<template>
  <n-flex :size="[5, 0]" justify="center" align="center">
    <slot></slot>
    <n-popover trigger="hover">
      <template #trigger>
        <n-button text>
          <template #icon>
            <n-icon :color="iconColor"><HelpFilled /></n-icon>
          </template>
        </n-button>
      </template>
      <slot name="msg"></slot>
    </n-popover>
  </n-flex>
</template>
