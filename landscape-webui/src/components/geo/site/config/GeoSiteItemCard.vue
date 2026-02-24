<script setup lang="ts">
import {
  delete_geo_site_config,
  update_geo_site_by_upload,
} from "@/api/geo/site";
import type { GeoSiteSourceConfig } from "landscape-types/api/schemas";
import { computed, ref } from "vue";
import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";
import { usePreferenceStore } from "@/stores/preference";
const prefStore = usePreferenceStore();

const frontEndStore = useFrontEndStore();
const emit = defineEmits(["refresh", "refresh:keys"]);

interface Prop {
  geo_site: GeoSiteSourceConfig;
}
const props = defineProps<Prop>();
const show_edit_modal = ref(false);

async function del() {
  if (props.geo_site.id) {
    await delete_geo_site_config(props.geo_site.id);
    emit("refresh");
  }
}

const title = computed(() => {
  return frontEndStore.presentation_mode
    ? mask_string(props.geo_site.name || "undefined")
    : props.geo_site.name || "undefined";
});

const show_upload = ref(false);
const onGeoUpload = async (formData: FormData) => {
  await update_geo_site_by_upload(props.geo_site.name, formData);
};
</script>
<template>
  <n-flex>
    <n-card size="small">
      <template #header>
        <StatusTitle :enable="geo_site.enable" :remark="title"></StatusTitle>
      </template>
      <n-descriptions bordered label-placement="top" :column="2">
        <n-descriptions-item label="来源类型">
          <n-tag
            :bordered="false"
            :type="geo_site.source.t === 'url' ? 'info' : 'success'"
            size="small"
          >
            {{ geo_site.source.t === "url" ? "URL" : "Direct" }}
          </n-tag>
        </n-descriptions-item>
        <template v-if="geo_site.source.t === 'url'">
          <n-descriptions-item label="URL">
            <n-ellipsis style="max-width: 200px">
              {{
                frontEndStore.presentation_mode
                  ? mask_string(geo_site.source.url)
                  : geo_site.source.url
              }}
            </n-ellipsis>
          </n-descriptions-item>
          <n-descriptions-item label="下次更新时间">
            <n-time
              :time="geo_site.source.next_update_at"
              format="yyyy-MM-dd hh:mm:ss"
              :time-zone="prefStore.timezone"
            />
          </n-descriptions-item>
        </template>
        <template v-if="geo_site.source.t === 'direct'">
          <n-descriptions-item label="Key 数量">
            {{ geo_site.source.data.length }}
          </n-descriptions-item>
        </template>
      </n-descriptions>
      <template #header-extra>
        <n-flex>
          <n-button
            v-if="geo_site.source.t === 'url'"
            size="small"
            type="info"
            secondary
            @click="show_upload = true"
          >
            使用文件更新
          </n-button>
          <n-button
            size="small"
            type="warning"
            secondary
            @click="show_edit_modal = true"
          >
            编辑
          </n-button>

          <n-popconfirm @positive-click="del()">
            <template #trigger>
              <n-button size="small" type="error" secondary @click="">
                删除
              </n-button>
            </template>
            确定删除吗
          </n-popconfirm>
        </n-flex>
      </template>
    </n-card>
    <GeoSiteEditModal
      :id="geo_site.id"
      @refresh="emit('refresh')"
      v-model:show="show_edit_modal"
    ></GeoSiteEditModal>
    <GeoUploadFile
      v-model:show="show_upload"
      :upload="onGeoUpload"
      @refresh="emit('refresh:keys')"
    ></GeoUploadFile>
  </n-flex>
</template>
