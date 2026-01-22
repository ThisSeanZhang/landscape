<script setup lang="ts">
import { computed } from "vue";
import { Range } from "@/lib/common";
const range = defineModel<Range>("range", { required: true });

const edit_range = computed({
  get() {
    return [range.value.start, range.value.end];
  },
  set(new_range: [number, number]) {
    let [start, end] = new_range;
    if (end > start) {
      range.value.start = start;
      range.value.end = end;
    }
  },
});
</script>

<template>
  <n-flex style="flex: 1" vertical>
    <n-slider
      :max="65535"
      :min="1"
      v-model:value="edit_range"
      range
      :step="1"
    />
    <n-flex style="flex: 1">
      <n-input-number
        style="flex: 1"
        v-model:value="range.start"
        size="small"
        :min="1"
        :max="65535"
        placeholder="Start"
      />
      <n-input-number
        style="flex: 1"
        v-model:value="range.end"
        size="small"
        :min="1"
        :max="65535"
        placeholder="End"
      />
    </n-flex>
  </n-flex>
</template>
