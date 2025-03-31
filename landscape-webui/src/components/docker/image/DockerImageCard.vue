<script setup lang="ts">
import { delete_docker_image } from "@/api/docker";
import { DockerImageSummary } from "@/lib/docker";
import { computed, ref } from "vue";

const props = defineProps<{
  image: DockerImageSummary;
}>();

const emit = defineEmits(["refresh"]);

const title = computed(() => {
  let t = "";
  if (props.image.RepoTags != undefined && props.image.RepoTags.length > 0) {
    t = props.image.RepoTags[0].replace(/^\/+/, "");
  }
  return t;
});

const time = computed(() => {
  let t = undefined;
  if (props.image.Created != undefined) {
    t = props.image.Created * 1000;
  }
  return t;
});

const size = computed(() => {
  let t = undefined;
  if (props.image.Size != undefined) {
    t = (props.image.Size / 1000 / 1000).toFixed(1);
  }
  return t;
});

async function delete_image() {
  if (props.image.Id != undefined) {
    try {
      await delete_docker_image(props.image.Id);
    } catch (e) {
    } finally {
      emit("refresh");
    }
  }
}

const show_create_model = ref(false);
</script>
<template>
  <n-card size="small">
    <template #header>
      <n-ellipsis>
        {{ props.image.Id }}
      </n-ellipsis>
    </template>
    <template #header-extra>
      <n-flex>
        <n-button
          strong
          secondary
          size="small"
          type="success"
          @click="show_create_model = true"
        >
          create
        </n-button>
        <n-button
          strong
          secondary
          size="small"
          type="error"
          @click="delete_image"
        >
          delete
        </n-button>
      </n-flex>
    </template>

    <n-descriptions :column="1" label-placement="left">
      <n-descriptions-item label="创建时间">
        <n-time v-if="time !== undefined" :time="time" />
        <span v-else>N/A</span>
      </n-descriptions-item>

      <n-descriptions-item label="大小">
        <span v-if="size !== undefined"> {{ size }} MB</span>
        <span v-else>N/A</span>
      </n-descriptions-item>
    </n-descriptions>

    <!-- {{ props.container }} -->

    <template #action>
      <n-tag v-for="tag of props.image.RepoTags" :bordered="false">
        {{ tag }}
      </n-tag>
    </template>
    <ContainerRunModal
      :image_name="title"
      v-model:show="show_create_model"
    ></ContainerRunModal>
  </n-card>
</template>
