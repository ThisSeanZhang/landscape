<script setup lang="ts">
import { onMounted, onBeforeUnmount } from "vue";
import { useDockerStore } from "@/stores/status_docker";
import useDockerImgTask from "@/stores/docker_img_task";
import DockerAllContainer from "@/components/docker/DockerAllContainer.vue";
import DockerStatusCard from "@/components/docker/DockerStatusCard.vue";

const dockerStore = useDockerStore();
const dockerImgTask = useDockerImgTask();

onMounted(() => {
  dockerStore.SET_ACTIVE(true);
  dockerImgTask.SET_ACTIVE(true);
});

onBeforeUnmount(() => {
  dockerStore.SET_ACTIVE(false);
  dockerImgTask.SET_ACTIVE(false);
  dockerImgTask.DISCONNECT();
});
</script>
<template>
  <n-layout :native-scrollbar="false" content-style="padding: 10px;">
    <n-flex style="flex: 1; padding-right: 15px" vertical>
      <n-flex><DockerStatusCard></DockerStatusCard> </n-flex>
      <n-flex style="flex: 1">
        <DockerAllContainer></DockerAllContainer>
      </n-flex>
    </n-flex>
  </n-layout>
</template>
