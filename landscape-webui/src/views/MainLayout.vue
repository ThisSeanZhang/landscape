<script setup lang="ts">
import { computed } from "vue";
import IntervalFetch from "@/components/head/IntervalFetch.vue";
import LanguageSetting from "@/components/head/LanguageSetting.vue";
import GlobalTerminal from "@/components/GlobalTerminal.vue";
import { usePtyStore } from "@/stores/pty";
import LandscapeSiderBar from "@/views/LandscapeSiderBar.vue";

const ptyStore = usePtyStore();

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
          <n-flex style="flex: 1" justify="space-between" align="center">
            <n-flex>/</n-flex>
            <n-flex>
              <PresentationMode></PresentationMode>
              <LanguageSetting />
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
