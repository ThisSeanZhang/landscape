<script setup lang="ts">
import { delete_docker_image } from "@/api/docker";
import { DockerImageSummary } from "@/lib/docker";
import { computed, ref } from "vue";
import { usePreferenceStore } from "@/stores/preference";
import { useI18n } from "vue-i18n";
const prefStore = usePreferenceStore();
const { t } = useI18n();

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

const loading = ref(false);
async function delete_image() {
  if (props.image.Id != undefined) {
    try {
      loading.value = true;
      await delete_docker_image(props.image.Id);
      emit("refresh");
    } catch (e) {
    } finally {
      loading.value = false;
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
          :loading="loading"
          @click="show_create_model = true"
        >
          {{ t("common.create") }}
        </n-button>

        <n-popconfirm @positive-click="delete_image">
          <template #trigger>
            <n-button
              strong
              secondary
              size="small"
              type="error"
              :loading="loading"
            >
              {{ t("common.delete") }}
            </n-button>
          </template>
          {{ t("common.confirm_delete") }}
        </n-popconfirm>
      </n-flex>
    </template>

    <n-descriptions :column="1" label-placement="left">
      <n-descriptions-item :label="t('common.created_at')">
        <n-time
          v-if="time !== undefined"
          :time="time"
          :time-zone="prefStore.timezone"
        />
        <span v-else>N/A</span>
      </n-descriptions-item>

      <n-descriptions-item label="大小">
        <span v-if="size !== undefined"> {{ size }} MB</span>
        <span v-else>N/A</span>
      </n-descriptions-item>
    </n-descriptions>

    <!-- {{ props.container }} -->

    <template #action>
      <n-flex>
        <n-tag v-for="tag of props.image.RepoTags" :bordered="false">
          {{ tag }}
        </n-tag>
      </n-flex>
    </template>
    <ContainerRunModal
      :image_name="title"
      v-model:show="show_create_model"
    ></ContainerRunModal>
  </n-card>
</template>
