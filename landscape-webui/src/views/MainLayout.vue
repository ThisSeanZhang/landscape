<script setup lang="ts">
import { computed, watch } from "vue";
import { useRouter, useRoute } from "vue-router";
import { useHistoryRouteStore } from "@/stores/history_route";

import { useI18n } from "vue-i18n";
import { useThemeVars } from "naive-ui";
import { Logout, Pin, PinFilled, Terminal } from "@vicons/carbon";
import { LANDSCAPE_TOKEN_KEY } from "@/lib/common";
import { useFrontEndStore } from "@/stores/front_end_config";
import { usePtyStore } from "@/stores/pty";
import IntervalFetch from "@/components/head/IntervalFetch.vue";
import LanguageSetting from "@/components/head/LanguageSetting.vue";
import GlobalTerminal from "@/components/GlobalTerminal.vue";
import LandscapeSiderBar from "@/views/LandscapeSiderBar.vue";

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

function handleTagClick(path: string) {
  router.push(path);
}

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

const frontEndStore = useFrontEndStore();
const ptyStore = usePtyStore();

function logout() {
  localStorage.removeItem(LANDSCAPE_TOKEN_KEY);
  frontEndStore.INSERT_USERNAME("");
  router.push("/login");
}

// Dynamic content style for Split Mode
const DOCK_SAFE_MARGIN = 8; // Safe distance from dock edge

const contentStyle = computed(() => {
  const baseStyle: any = {
    top: "40px",
    left: "25px",
    display: "flex",
    paddingRight: "15px",
    transition: "all 0.3s ease",
  };

  if (ptyStore.viewMode === "dock" && ptyStore.isOpen) {
    if (ptyStore.dockPosition === "bottom") {
      baseStyle.bottom = `${ptyStore.dockSize + DOCK_SAFE_MARGIN}px`;
      baseStyle.right = "0px";
    } else if (ptyStore.dockPosition === "right") {
      baseStyle.bottom = "0px";
      baseStyle.right = `${ptyStore.dockSize + DOCK_SAFE_MARGIN}px`;
    }
  } else {
    baseStyle.bottom = "0px";
    baseStyle.right = "0px";
  }

  return baseStyle;
});
</script>

<template>
  <div style="flex: 1">
    <n-layout position="absolute" has-sider>
      <LandscapeSiderBar />
      <n-layout>
        <n-layout-header
          style="height: 30px; padding: 0 10px; display: flex"
          bordered
        >
          <n-flex
            style="flex: 1; width: 0"
            justify="space-between"
            align="center"
            :wrap="false"
          >
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
                  @click="handleTagClick(tag.path)"
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
                    <span style="margin: 0 4px">{{
                      t(tag.name) || "Dashboard"
                    }}</span>
                  </n-flex>
                </n-tag>
              </n-flex>
            </n-scrollbar>

            <n-flex :size="[5, 0]">
              <LanguageSetting />
              <PresentationMode></PresentationMode>
              <n-flex align="center">
                <n-button
                  quaternary
                  circle
                  size="small"
                  @click="ptyStore.toggleOpen"
                  title="WebShell"
                >
                  <template #icon>
                    <n-icon><Terminal /></n-icon>
                  </template>
                </n-button>
              </n-flex>
              <n-flex align="center">
                <n-button
                  quaternary
                  circle
                  size="small"
                  @click="logout"
                  :title="t('common.logout')"
                >
                  <template #icon>
                    <n-icon><Logout /></n-icon>
                  </template>
                </n-button>
              </n-flex>
              <IntervalFetch />
            </n-flex>
          </n-flex>
        </n-layout-header>

        <GlobalTerminal />

        <n-layout
          :native-scrollbar="false"
          position="absolute"
          :style="contentStyle"
          content-style="flex:1; display: flex; height: 100%;"
          content-class="main-body"
        >
          <RouterView />
        </n-layout>
      </n-layout>
    </n-layout>
  </div>
</template>
