<script setup lang="ts">
import { run_cmd } from "@/api/docker";
import { KeyValuePair } from "@/lib/common";
import { DockerCmd } from "@/lib/docker";
import { useDockerStore } from "@/stores/status_docker";
import { useNotification } from "naive-ui";
import { computed, ref } from "vue";

const show_model = defineModel<boolean>("show", { required: true });

const emit = defineEmits(["refresh"]);

const notification = useNotification();

async function pull_image() {}
</script>

<template>
  <n-modal :auto-focus="false" v-model:show="show_model">
    <n-card
      style="width: 600px"
      title="拉取镜像"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <template #footer>
        <n-flex justify="end">
          <n-button round type="primary" @click="pull_image"> 拉取 </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
