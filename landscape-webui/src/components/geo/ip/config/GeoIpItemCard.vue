<script setup lang="ts">
import { delete_geo_ip_config, update_geo_ip_by_upload } from "@/api/geo/ip";
import { GeoIpSourceConfig } from "@/rust_bindings/common/geo_ip";
import { computed, ref } from "vue";
import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";

const frontEndStore = useFrontEndStore();
const emit = defineEmits(["refresh", "refresh:keys"]);

interface Prop {
  geo_ip_source: GeoIpSourceConfig;
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
  if (props.geo_ip_source.name) {
    return props.geo_ip_source.name;
  } else {
    return "undefined";
  }
});

const show_upload = ref(false);
const onGeoUpload = async (formData: FormData) => {
  await update_geo_ip_by_upload(props.geo_ip_source.name, formData);
};

// 格式化时间戳为年月日时分秒
const formatTimestamp = (timestamp: number) => {
  if (timestamp === 0) {
    return "未设置";
  }
  const date = new Date(timestamp);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
};
</script>
<template>
  <n-flex>
    <n-card :title="title" size="small">
      <!-- {{ geo_ip_source }} -->
      <n-descriptions bordered label-placement="top" :column="3">
        <n-descriptions-item label="名称">
          {{
            frontEndStore.presentation_mode
              ? mask_string(geo_ip_source.name)
              : geo_ip_source.name
          }}
        </n-descriptions-item>
        <n-descriptions-item label="启用">
          {{ geo_ip_source.enable }}
        </n-descriptions-item>
        <n-descriptions-item label="URL">
          {{
            frontEndStore.presentation_mode
              ? mask_string(geo_ip_source.url)
              : geo_ip_source.url
          }}
        </n-descriptions-item>
        <n-descriptions-item label="下次更新时间">
          {{ formatTimestamp(geo_ip_source.next_update_at) }}
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
