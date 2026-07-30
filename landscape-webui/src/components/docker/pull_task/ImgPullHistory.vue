<script setup lang="ts">
import { get_docker_images, pull_docker_image } from "@/api/docker";
import { ref } from "vue";
import DockerImageCard from "@/components/docker/image/DockerImageCard.vue";
import { useI18n } from "vue-i18n";
const { t } = useI18n();
const show = defineModel<boolean>("show", { required: true });

import useDockerImgTask from "@/stores/docker_img_task";

const emit = defineEmits(["refresh"]);

const dockerImgTask = useDockerImgTask();
async function flush_tasks() {
  await dockerImgTask.INIT();
}

function leave() {
  emit("refresh");
}
</script>
<template>
  <n-drawer
    @after-enter="flush_tasks()"
    @after-leave="leave"
    v-model:show="show"
    width="500px"
    placement="right"
    responsive
  >
    <n-drawer-content
      :title="t('docker.docker_pull.download_history')"
      closable
    >
      <n-flex style="height: 100%" vertical>
        <n-scrollbar>
          <n-flex>
            <PullTaskCard
              v-for="task in dockerImgTask.tasks"
              :key="task.id"
              :task="task"
            >
            </PullTaskCard>
          </n-flex>
        </n-scrollbar>
      </n-flex>
    </n-drawer-content>
  </n-drawer>
</template>
