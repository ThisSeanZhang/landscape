<script setup lang="ts">
import { computed, ref } from "vue";

import { DotMark } from "@vicons/carbon";
import { useThemeVars } from "naive-ui";

import { ServiceStatusType } from "@/lib/services";
import { useDockerStore } from "@/stores/status_docker";

import DockerImageDrawer from "@/components/docker/DockerImageDrawer.vue";
import {
  start_docker_service,
  stop_docker_service,
} from "@/api/docker_service";

const dockerStatus = useDockerStore();
const themeVars = ref(useThemeVars());
const show_image_drawer = ref(false);

const is_down = computed(() => {
  return dockerStatus.docker_status.t == ServiceStatusType.Stop;
});

async function start() {
  await start_docker_service();
}
async function stop() {
  await stop_docker_service();
}
</script>
<template>
  <n-card content-style="display: flex;">
    <template #header>
      <n-icon
        :color="dockerStatus.docker_status.get_color(themeVars)"
        size="16"
      >
        <DotMark />
      </n-icon>
      Docker
    </template>
    <template #header-extra>
      <n-flex>
        <n-button @click="show_image_drawer = true">查看镜像</n-button>
        <n-button @click="start" v-if="is_down"> 开启 </n-button>
        <n-button v-else @click="stop">关闭 docker 事件监听服务</n-button>
      </n-flex>
    </template>
    <n-flex justify="center" align="center" style="flex: 1">
      <n-empty description="TODO"> </n-empty>
    </n-flex>
    <!-- // TODO 展示使用资源
    {{ dockerStatus.docker_status }} -->
    <!-- <template #footer> #footer </template>
    <template #action> #action </template> -->
    <DockerImageDrawer v-model:show="show_image_drawer" />
  </n-card>
</template>
