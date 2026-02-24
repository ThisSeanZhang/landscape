<script setup lang="ts">
import type {
  PullImgTask,
  PullImgTaskItem,
} from "@landscape-router/types/api/schemas";
import { Task } from "@vicons/carbon";
import { computed } from "vue";

const props = defineProps<{
  task: PullImgTask;
}>();

function calculate_percentage(layer: PullImgTaskItem | undefined): string {
  if (layer) {
    if (layer.current != null && layer.total != null) {
      return ((layer.current * 100) / layer.total).toFixed(1);
    }
  }
  return "0";
}
</script>

<template>
  <n-card>
    <template #header>
      {{ task.img_name }}
    </template>
    <n-flex vertical>
      <n-progress
        v-for="layer in task.layer_current_info"
        type="line"
        :percentage="calculate_percentage(layer)"
        indicator-placement="inside"
      >
        [{{ layer?.id }}][{{ layer?.current }}/{{ layer?.total }}]-{{
          calculate_percentage(layer)
        }}%
      </n-progress>
    </n-flex>
    <!-- {{ task }} -->
  </n-card>
</template>
