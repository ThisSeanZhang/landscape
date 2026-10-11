<script setup lang="ts">
import {
  cancel_geo_ip_task,
  delete_geo_ip_config,
  refresh_geo_ip_by_name,
  update_geo_ip_by_upload,
} from "@/api/geo/ip";
import type {
  GeoIpSourceConfig,
  GeoTaskProgress,
} from "@landscape-router/types/api/schemas";
import { computed, ref } from "vue";
import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";
import { formatSize } from "@/lib/util";
import { usePreferenceStore } from "@/stores/preference";
import { useI18n } from "vue-i18n";
const prefStore = usePreferenceStore();

const frontEndStore = useFrontEndStore();
const { t } = useI18n();
const emit = defineEmits(["refresh", "refresh:keys", "refresh:tasks"]);

interface Prop {
  geo_ip_source: GeoIpSourceConfig;
  task?: GeoTaskProgress;
}
const props = defineProps<Prop>();
const show_edit_modal = ref(false);

async function del() {
  if (props.geo_ip_source.id) {
    await delete_geo_ip_config(props.geo_ip_source.id);
    emit("refresh");
  }
}

const title = computed(() => {
  return frontEndStore.presentation_mode
    ? mask_string(props.geo_ip_source.name || "undefined")
    : props.geo_ip_source.name || "undefined";
});

const show_upload = ref(false);
const onGeoUpload = async (formData: FormData) => {
  await update_geo_ip_by_upload(props.geo_ip_source.name, formData);
  emit("refresh:tasks");
};

const phase_label = computed(() => {
  if (!props.task) return "";
  return t(`geo.phase_${props.task.phase}`);
});

const download_label = computed(() => {
  if (!props.task || props.task.phase !== "downloading") return "";
  if (!props.task.bytes_done) return "";
  const done = formatSize(props.task.bytes_done);
  return props.task.bytes_total
    ? `${done} / ${formatSize(props.task.bytes_total)}`
    : done;
});

async function cancel_task() {
  if (props.geo_ip_source.id) {
    await cancel_geo_ip_task(props.geo_ip_source.id);
    emit("refresh:tasks");
  }
}

async function force_refresh() {
  await refresh_geo_ip_by_name(props.geo_ip_source.name);
  emit("refresh:tasks");
}
</script>
<template>
  <n-flex>
    <n-card size="small">
      <template #header>
        <StatusTitle
          :enable="geo_ip_source.enable"
          :remark="title"
        ></StatusTitle>
      </template>
      <n-descriptions bordered label-placement="top" :column="2">
        <n-descriptions-item :label="t('geo.item_card.source_type')">
          <n-tag
            :bordered="false"
            :type="geo_ip_source.source.t === 'url' ? 'info' : 'success'"
            size="small"
          >
            {{ geo_ip_source.source.t === "url" ? "URL" : "Direct" }}
          </n-tag>
        </n-descriptions-item>
        <template v-if="geo_ip_source.source.t === 'url'">
          <n-descriptions-item :label="t('geo.item_card.source_format')">
            <n-tag
              :bordered="false"
              :type="
                (geo_ip_source.source.format || 'dat') === 'txt'
                  ? 'warning'
                  : 'info'
              "
              size="small"
            >
              {{ (geo_ip_source.source.format || "dat").toUpperCase() }}
            </n-tag>
          </n-descriptions-item>
          <n-descriptions-item label="URL">
            <n-ellipsis style="max-width: 200px">
              {{
                frontEndStore.presentation_mode
                  ? mask_string(geo_ip_source.source.url)
                  : geo_ip_source.source.url
              }}
            </n-ellipsis>
          </n-descriptions-item>
          <n-descriptions-item :label="t('geo.item_card.next_update_time')">
            <n-time
              :time="geo_ip_source.source.next_update_at"
              format="yyyy-MM-dd hh:mm:ss"
              :time-zone="prefStore.timezone"
            />
          </n-descriptions-item>
          <n-descriptions-item
            v-if="(geo_ip_source.source.format || 'dat') === 'txt'"
            :label="t('geo.item_card.txt_key')"
          >
            {{ (geo_ip_source.source.txt_key || "DEFAULT").toUpperCase() }}
          </n-descriptions-item>
        </template>
        <template v-if="geo_ip_source.source.t === 'direct'">
          <n-descriptions-item :label="t('geo.item_card.key_count')">
            {{ geo_ip_source.source.data.length }}
          </n-descriptions-item>
        </template>
        <n-descriptions-item v-if="task" :label="t('geo.task_status')">
          <n-flex align="center" :size="6">
            <n-tag size="small" type="info">{{ phase_label }}</n-tag>
            <span v-if="download_label" style="font-size: 12px">
              {{ download_label }}
            </span>
          </n-flex>
        </n-descriptions-item>
      </n-descriptions>
      <template #header-extra>
        <n-flex>
          <n-popconfirm v-if="task" @positive-click="cancel_task">
            <template #trigger>
              <n-button size="small" type="warning" secondary>
                {{ t("geo.cancel_task") }}
              </n-button>
            </template>
            {{ t("geo.confirm_cancel_task") }}
          </n-popconfirm>
          <n-button
            v-if="geo_ip_source.source.t === 'url'"
            size="small"
            type="info"
            secondary
            @click="show_upload = true"
          >
            {{ t("geo.item_card.update_with_file") }}
          </n-button>

          <n-popconfirm
            v-if="geo_ip_source.source.t === 'url'"
            @positive-click="force_refresh"
          >
            <template #trigger>
              <n-button size="small" type="primary" secondary>
                {{ t("geo.item_card.force_refresh") }}
              </n-button>
            </template>
            {{ t("geo.item_card.force_refresh_confirm") }}
          </n-popconfirm>

          <n-button
            size="small"
            type="warning"
            secondary
            @click="show_edit_modal = true"
          >
            {{ t("common.edit") }}
          </n-button>

          <n-popconfirm @positive-click="del()">
            <template #trigger>
              <n-button size="small" type="error" secondary @click="">
                {{ t("common.delete") }}
              </n-button>
            </template>
            {{ t("common.confirm_delete") }}
          </n-popconfirm>
        </n-flex>
      </template>
    </n-card>
    <GeoIpEditModal
      :id="geo_ip_source.id"
      @refresh="emit('refresh')"
      v-model:show="show_edit_modal"
    ></GeoIpEditModal>

    <GeoUploadFile
      v-model:show="show_upload"
      :upload="onGeoUpload"
      @refresh="emit('refresh:keys')"
    ></GeoUploadFile>
  </n-flex>
</template>
