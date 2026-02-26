<script setup lang="ts">
import { run_cmd } from "@/api/docker";
import { KeyValuePair } from "@/lib/common";
import { useDockerStore } from "@/stores/status_docker";
import { useNotification } from "naive-ui";
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";

const show_model = defineModel<boolean>("show", { required: true });

const emit = defineEmits(["refresh"]);
const { t } = useI18n();

const notification = useNotification();

async function pull_image() {}
</script>

<template>
  <n-modal :auto-focus="false" v-model:show="show_model">
    <n-card
      style="width: 600px"
      :title="t('common.pull_image')"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <template #footer>
        <n-flex justify="end">
          <n-button round type="primary" @click="pull_image">
            {{ t("common.pull_image") }}
          </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
