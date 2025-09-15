<script setup lang="ts">
import { ExhibitType } from "@/lib/sys";
import { NProgress } from "naive-ui";
import { useThemeVars } from "naive-ui";
// import {get_cpu} from "./api/sys";
import { changeColor } from "seemly";
import { computed, ref } from "vue";

interface Props {
  value: number;
  exhibit_type?: ExhibitType;
  label?: string; // 新增的label属性
  showLabel?: boolean; // 控制是否显示label
  labelPosition?: "inside" | "outside"; // label显示位置
}

const warn = defineModel("warn", { default: true });

const props = withDefaults(defineProps<Props>(), {
  exhibit_type: ExhibitType.Dashboard,
  label: "",
  showLabel: true,
  labelPosition: "inside",
});

const themeVars = ref(useThemeVars());

const percentage = computed(() => {
  return parseFloat((props.value * 100).toFixed(1));
});

const displayText = computed(() => {
  return props.label
    ? `${props.label}: ${percentage.value}%`
    : `${percentage.value}%`;
});

const percentage_color = computed(() => {
  if (warn.value) {
    if (percentage.value > 90) {
      return themeVars.value.errorColor;
    } else if (percentage.value > 80) {
      return themeVars.value.warningColor;
    } else {
      return themeVars.value.successColor;
    }
  } else {
    return themeVars.value.successColor;
  }
});
</script>
<template>
  <!-- {{ themeVars }} -->
  <n-progress
    v-if="props.exhibit_type === ExhibitType.Dashboard"
    type="dashboard"
    gap-position="bottom"
    :color="percentage_color"
    :rail-color="changeColor(percentage_color, { alpha: 0.2 })"
    :percentage="percentage"
  >
    <template v-if="props.showLabel" #default>
      <n-tooltip trigger="hover">
        <template #trigger>
          <span :style="{ color: percentage_color, fontSize: '20px' }">
            {{ percentage }}%
          </span>
        </template>
        {{ label }}
      </n-tooltip>
    </template>
  </n-progress>

  <n-progress
    v-else-if="props.exhibit_type === ExhibitType.Line"
    type="line"
    :color="percentage_color"
    :rail-color="changeColor(percentage_color, { alpha: 0.2 })"
    :percentage="percentage"
    :indicator-placement="props.labelPosition"
    :indicator-text="props.showLabel ? displayText : undefined"
  />
</template>
