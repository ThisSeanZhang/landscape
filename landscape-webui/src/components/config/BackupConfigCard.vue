<script setup lang="ts">
import { get_init_config, import_init_config } from "@/api/sys/config";
import type { UploadFileInfo } from "naive-ui";
import { useMessage } from "naive-ui";
import { ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();
const message = useMessage();

const import_loading = ref(false);
const upload_only = ref(true);
const file_list = ref<UploadFileInfo[]>([]);

async function export_file() {
  await get_init_config();
}

async function import_file() {
  const file = file_list.value[0]?.file as File | undefined;
  if (!file) {
    message.warning(t("config.import_file_required"));
    return;
  }

  import_loading.value = true;
  try {
    const result = await import_init_config(file, upload_only.value);
    if (result.upload_only) {
      message.success(
        t("config.import_validate_success", { version: result.version }),
      );
    } else {
      message.success(
        t("config.import_install_success", { version: result.version }),
      );
      file_list.value = [];
    }
  } finally {
    import_loading.value = false;
  }
}
</script>

<template>
  <n-card :title="t('config.backup_title')" segmented id="backup-config">
    <n-p>
      {{ t("config.backup_desc") }}
    </n-p>
    <n-button @click="export_file" type="info" ghost>
      {{ t("config.export_init") }}
    </n-button>

    <n-divider />

    <n-p>
      {{ t("config.import_init_desc") }}
    </n-p>
    <n-space vertical :size="12">
      <n-upload
        v-model:file-list="file_list"
        :max="1"
        accept=".toml"
        :default-upload="false"
      >
        <n-button>{{ t("config.select_init_file") }}</n-button>
      </n-upload>
      <n-space align="center">
        <n-switch v-model:value="upload_only" />
        <n-text>{{ t("config.upload_only") }}</n-text>
      </n-space>
      <n-alert v-if="!upload_only" type="warning" :show-icon="false">
        {{ t("config.import_install_warning") }}
      </n-alert>
      <n-button
        type="warning"
        ghost
        :loading="import_loading"
        @click="import_file"
      >
        {{ t("config.import_init") }}
      </n-button>
    </n-space>
  </n-card>
</template>
