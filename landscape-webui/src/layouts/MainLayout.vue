<script setup lang="ts">
import { ref, watch } from "vue";
import { useRouter, useRoute } from "vue-router";
import RouteTabs from "@/components/layout/header/RouteTabs.vue";

import { useI18n } from "vue-i18n";
import { Logout, Menu, Terminal } from "@vicons/carbon";
import { LANDSCAPE_TOKEN_KEY } from "@/lib/common";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useCapabilityStore } from "@/stores/capability";
import { usePtyStore } from "@/stores/pty";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";
import IntervalFetch from "@/components/layout/header/IntervalFetch.vue";
import GlobalTerminal from "@/components/GlobalTerminal.vue";
import LandscapeSiderBar from "@/layouts/LandscapeSiderBar.vue";

import { useMobileLayout } from "@/composables/useMobileLayout";

const mobile = useMobileLayout();
const menuOpen = ref(false);
watch(mobile, () => {
  menuOpen.value = false;
});

const router = useRouter();
const route = useRoute();
const { t } = useI18n();

const frontEndStore = useFrontEndStore();
const capabilityStore = useCapabilityStore();
const ptyStore = usePtyStore();
const enrolledDeviceStore = useEnrolledDeviceStore();

void capabilityStore.LOAD();

watch(
  () => route.path,
  () => {
    menuOpen.value = false;
    void enrolledDeviceStore.UPDATE_INFO();
  },
  { immediate: true },
);

function logout() {
  localStorage.removeItem(LANDSCAPE_TOKEN_KEY);
  frontEndStore.INSERT_USERNAME("");
  router.push("/login");
}
</script>

<template>
  <div style="flex: 1">
    <n-layout position="absolute" has-sider>
      <LandscapeSiderBar :mobile="mobile" v-model:open="menuOpen" />
      <n-layout>
        <n-layout-header class="app-header" bordered>
          <n-flex
            style="flex: 1; width: 0"
            justify="space-between"
            align="center"
            :wrap="false"
          >
            <n-button
              v-if="mobile"
              quaternary
              circle
              :aria-label="t('common.navigation')"
              :aria-expanded="menuOpen"
              @click="menuOpen = true"
            >
              <template #icon><n-icon :component="Menu" /></template>
            </n-button>
            <RouteTabs />

            <n-flex :size="[5, 0]">
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

        <div
          class="workspace"
          :class="{ 'dock-bottom': ptyStore.dockPosition === 'bottom' }"
        >
          <GlobalTerminal />
          <n-layout
            :native-scrollbar="false"
            class="layout-content"
            content-style="flex:1; display: flex; height: 100%;"
            content-class="main-body"
          >
            <RouterView :key="route.name" />
          </n-layout>
        </div>
      </n-layout>
    </n-layout>
  </div>
</template>

<style scoped>
.app-header {
  height: 30px;
  padding: 0 10px;
  display: flex;
}
.workspace {
  position: absolute;
  inset: 40px 0 0 25px;
  display: flex;
  flex-direction: row-reverse;
  gap: 8px;
}
.workspace.dock-bottom {
  flex-direction: column-reverse;
}
.layout-content {
  flex: 1;
  min-width: 0;
  min-height: 0;
  display: flex;
  padding-right: 15px;
}
@media (max-width: 768px) {
  .app-header {
    height: 44px;
    padding: 0 8px;
  }
  .workspace {
    inset: 54px 0 0 12px;
  }
  .layout-content {
    padding-right: 12px;
  }
}
</style>
