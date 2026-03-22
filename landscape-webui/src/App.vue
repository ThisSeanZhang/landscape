<script setup lang="ts">
import { darkTheme, enUS, zhCN, dateZhCN, dateEnUS } from "naive-ui";
import { computed, onMounted } from "vue";
import { usePreferenceStore } from "@/stores/preference";
import Env from "@/components/Env.vue";

const prefStore = usePreferenceStore();

onMounted(() => {
  prefStore.loadPreference();
});

const currentLocale = computed(() => {
  return prefStore.language?.startsWith("en") ? enUS : zhCN;
});

const currentDateLocale = computed(() => {
  return prefStore.language?.startsWith("en") ? dateEnUS : dateZhCN;
});

const currentTheme = computed(() => {
  return prefStore.theme === "light" ? null : darkTheme;
});
</script>

<template>
  <n-config-provider
    :locale="currentLocale"
    :date-locale="currentDateLocale"
    :theme="currentTheme"
    style="display: flex; flex: 1"
    :theme-overrides="{ common: { fontWeightStrong: '600' } }"
  >
    <n-message-provider>
      <n-notification-provider>
        <n-dialog-provider>
          <Env></Env>
          <RouterView />
        </n-dialog-provider>
      </n-notification-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<style>
/* .main-body {
  align-items: center;
  width: 100%;
  display: flex;
  justify-items: center;
} */
</style>
