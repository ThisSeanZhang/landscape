<script setup lang="ts">
import {
  delete_geo_site_config,
  update_geo_site_by_upload,
} from "@/api/geo/site";
import { GeoSiteSourceConfig } from "@/rust_bindings/common/geo_site";
import { computed, ref } from "vue";
import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";

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
  if (props.geo_site.name) {
    return props.geo_site.name;
  } else {
    return "undefined";
  }
});

const show_upload = ref(false);
const onGeoUpload = async (formData: FormData) => {
  await update_geo_site_by_upload(props.geo_site.name, formData);
};
</script>
<template>
  <n-flex>
    <n-card :title="title" size="small">
      <!-- {{ geo_site }} -->
      <n-descriptions bordered label-placement="top" :column="3">
        <n-descriptions-item label="名称">
          {{
            frontEndStore.presentation_mode
              ? mask_string(geo_site.name)
              : geo_site.name
          }}
        </n-descriptions-item>
        <n-descriptions-item label="启用">
          {{ geo_site.enable }}
        </n-descriptions-item>
        <n-descriptions-item label="URL">
          {{
            frontEndStore.presentation_mode
              ? mask_string(geo_site.url)
              : geo_site.url
          }}
        </n-descriptions-item>
        <n-descriptions-item label="下次更新时间">
          {{ geo_site.next_update_at }}
        </n-descriptions-item>
      </n-descriptions>
      <template #header-extra>
        <n-flex>
          <n-button type="info" secondary @click="show_upload = true">
            使用文件更新
          </n-button>
          <n-button type="warning" secondary @click="show_edit_modal = true">
            编辑
          </n-button>

          <n-popconfirm @positive-click="del()">
            <template #trigger>
              <n-button type="error" secondary @click=""> 删除 </n-button>
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
