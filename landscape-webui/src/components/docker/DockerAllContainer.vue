<script setup lang="ts">
import { useDockerStore } from "@/stores/status_docker";
import DockerContainerCard from "@/components/docker/DockerContainerCard.vue";

const dockerStatus = useDockerStore();
</script>
<template>
  <n-grid x-gap="12" y-gap="12" :cols="4">
    <n-gi style="display: flex;" :span="1" v-for="container in dockerStatus.container_summarys">
      <!-- {{ container }} -->
      <DockerContainerCard :container="container" />
    </n-gi>
  </n-grid>
</template>
