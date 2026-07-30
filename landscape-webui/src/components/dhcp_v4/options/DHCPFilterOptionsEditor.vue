<script setup lang="ts">
import { DHCP_FILTER_OPTIONS, DHCP_OPTION_LABELS } from "./types";

const model = defineModel<number[]>({ required: true });

const options = DHCP_FILTER_OPTIONS.map((code: number) => ({
  label: DHCP_OPTION_LABELS[code] ?? `Option ${code}`,
  value: code,
}));
</script>

<template>
  <n-select
    v-model:value="model"
    :options="options"
    multiple
    clearable
    :placeholder="$t('device.filter_options_placeholder')"
  />
</template>
