<script setup lang="ts">
import { watch } from "vue";
import { useRouter, useRoute } from "vue-router";
import { useHistoryRouteStore } from "@/stores/history_route";
import { useI18n } from "vue-i18n";
import { useThemeVars } from "naive-ui";
import { Pin, PinFilled } from "@vicons/carbon";

const router = useRouter();
const route = useRoute();
const historyStore = useHistoryRouteStore();
const { t } = useI18n();

const themeVars = useThemeVars();

watch(
  () => route.path,
  () => {
    historyStore.addRoute(route);
  },
  { immediate: true },
);

function handleTagClose(path: string) {
  historyStore.removeRoute(path);
  if (path === route.path) {
    const lastRoute =
      historyStore.visitedRoutes[historyStore.visitedRoutes.length - 1];
    if (lastRoute) {
      router.push(lastRoute.path);
    } else {
      router.push("/");
    }
  }
}
</script>

<template>
  <n-scrollbar
    x-scrollable
    style="flex: 1; min-width: 0; margin-right: 10px"
    content-style="display: flex; align-items: center; height: 100%"
  >
    <n-flex align="center" :wrap="false" size="small">
      <n-tag
        v-for="tag in historyStore.visitedRoutes"
        :key="tag.path"
        :type="tag.path === route.path ? 'primary' : 'default'"
        :closable="!tag.pinned"
        @click="router.push(tag.path)"
        @close.stop="handleTagClose(tag.path)"
        style="
          cursor: pointer;
          padding: 0 8px;
          height: 23px;
          display: flex;
          align-items: center;
        "
        size="small"
        :bordered="false"
      >
        <n-flex align="center" :size="4" :wrap="false">
          <n-icon
            @click.stop="historyStore.togglePin(tag.path)"
            :size="16"
            :color="tag.pinned ? themeVars.infoColor : undefined"
            class="pin-icon"
            :component="tag.pinned ? PinFilled : Pin"
          >
          </n-icon>
          <span style="margin: 0 4px">{{ t(tag.name) || "Dashboard" }}</span>
        </n-flex>
      </n-tag>
    </n-flex>
  </n-scrollbar>
</template>
