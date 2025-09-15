<script setup lang="ts">
import { useThemeVars } from "naive-ui";
import { ref } from "vue";
import { DotMark } from "@vicons/carbon";

const themeVars = ref(useThemeVars());

type Props = {
  enable: boolean;
  remark: string;
};

const props = defineProps<Props>();
</script>
<template>
  <n-flex align="center" :size="[3, 0]" :wrap="false">
    <n-icon :color="enable ? themeVars.successColor : ''" size="14">
      <DotMark />
    </n-icon>
    <n-ellipsis>
      {{ remark !== "" ? remark : "无备注" }}
    </n-ellipsis>
  </n-flex>
</template>
