<script setup lang="ts">
import { ref, watch } from "vue";
import type { RelayAgentInfo } from "@landscape-router/types/api/schemas";

const model = defineModel<RelayAgentInfo>({ required: true });
const invalidJson = ref(false);
const jsonText = ref(JSON.stringify(model.value ?? {}, null, 2));

watch(
  model,
  (value) => {
    const nextText = JSON.stringify(value ?? {}, null, 2);
    if (!invalidJson.value && jsonText.value !== nextText) {
      jsonText.value = nextText;
    }
  },
  { deep: true },
);

function onUpdateValue(value: string) {
  jsonText.value = value;
  try {
    const parsed = JSON.parse(value);
    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed)
    ) {
      invalidJson.value = true;
      model.value = null as unknown as RelayAgentInfo;
      return;
    }
    invalidJson.value = false;
    model.value = parsed as RelayAgentInfo;
  } catch {
    invalidJson.value = true;
    model.value = null as unknown as RelayAgentInfo;
  }
}
</script>

<template>
  <n-input
    :value="jsonText"
    placeholder='e.g. {"AgentCircuitId":"010203"}'
    type="textarea"
    :status="invalidJson ? 'error' : undefined"
    :autosize="{ minRows: 2, maxRows: 4 }"
    style="width: 100%"
    @update:value="onUpdateValue"
  />
</template>
