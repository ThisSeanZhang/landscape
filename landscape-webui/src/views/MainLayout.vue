<script setup lang="ts">
import { computed, watch } from "vue";
import { useRouter, useRoute } from "vue-router";
import RouteTabs from "@/components/head/RouteTabs.vue";

import { useI18n } from "vue-i18n";
import { Logout, Terminal } from "@vicons/carbon";
import { LANDSCAPE_TOKEN_KEY } from "@/lib/common";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useCapabilityStore } from "@/stores/capability";
import { usePtyStore } from "@/stores/pty";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";
import IntervalFetch from "@/components/head/IntervalFetch.vue";
import LanguageSetting from "@/components/head/LanguageSetting.vue";
import GlobalTerminal from "@/components/GlobalTerminal.vue";
import LandscapeSiderBar from "@/views/LandscapeSiderBar.vue";

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
    void enrolledDeviceStore.UPDATE_INFO();
  },
  { immediate: true },
);

function logout() {
  localStorage.removeItem(LANDSCAPE_TOKEN_KEY);
  frontEndStore.INSERT_USERNAME("");
  router.push("/login");
}

const dockOffset = computed(() =>
  ptyStore.viewMode === "dock" && ptyStore.isOpen ? ptyStore.dockSize + 8 : 0,
);
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
            <RouteTabs />

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
          class="layout-content"
          :style="{
            bottom:
              ptyStore.dockPosition === 'bottom' ? dockOffset + 'px' : '0px',
            right:
              ptyStore.dockPosition === 'right' ? dockOffset + 'px' : '0px',
          }"
          content-style="flex:1; display: flex; height: 100%;"
          content-class="main-body"
        >
          <RouterView :key="route.name" />
        </n-layout>
      </n-layout>
    </n-layout>
  </div>
</template>

<style scoped>
.layout-content {
  top: 40px;
  left: 25px;
  display: flex;
  padding-right: 15px;
  transition: all 0.3s ease;
}
</style>
