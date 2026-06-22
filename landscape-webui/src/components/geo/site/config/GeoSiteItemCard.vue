<script setup lang="ts">
import {
  delete_geo_site_config,
  refresh_geo_site_by_name,
  update_geo_site_by_upload,
} from "@/api/geo/site";
import type { GeoSiteSourceConfig } from "@landscape-router/types/api/schemas";
import { computed, ref } from "vue";
import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";
import { usePreferenceStore } from "@/stores/preference";
import { useI18n } from "vue-i18n";
const prefStore = usePreferenceStore();

const frontEndStore = useFrontEndStore();
const { t } = useI18n();
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

const refreshing = ref(false);
async function force_refresh() {
  refreshing.value = true;
  try {
    await refresh_geo_site_by_name(props.geo_site.name);
    emit("refresh");
    emit("refresh:keys");
  } finally {
    refreshing.value = false;
  }
}
</script>
<template>
  <n-flex>
    <n-card size="small">
      <template #header>
        <StatusTitle :enable="geo_site.enable" :remark="title"></StatusTitle>
      </template>
      <n-descriptions bordered label-placement="top" :column="2">
        <n-descriptions-item :label="t('geo_editor.item_card.source_type')">
          <n-tag
            :bordered="false"
            :type="
              geo_site.source.t === 'url'
                ? 'info'
                : geo_site.source.t === 'adguard_home'
                  ? 'warning'
                  : 'success'
            "
            size="small"
          >
            {{
              geo_site.source.t === "url"
                ? "URL"
                : geo_site.source.t === "adguard_home"
                  ? "AdGuard"
                  : "Direct"
            }}
          </n-tag>
        </n-descriptions-item>
        <template
          v-if="
            geo_site.source.t === 'url' || geo_site.source.t === 'adguard_home'
          "
        >
          <n-descriptions-item label="URL">
            <n-ellipsis style="max-width: 200px">
              {{
                frontEndStore.presentation_mode
                  ? mask_string(geo_site.source.url)
                  : geo_site.source.url
              }}
            </n-ellipsis>
          </n-descriptions-item>
          <n-descriptions-item
            :label="t('geo_editor.item_card.next_update_time')"
          >
            <n-time
              :time="geo_site.source.next_update_at"
              format="yyyy-MM-dd hh:mm:ss"
              :time-zone="prefStore.timezone"
            />
          </n-descriptions-item>
        </template>
        <template v-if="geo_site.source.t === 'direct'">
          <n-descriptions-item :label="t('geo_editor.item_card.key_count')">
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
            {{ t("geo_editor.item_card.update_with_file") }}
          </n-button>
          <n-popconfirm
            v-if="
              geo_site.source.t === 'url' ||
              geo_site.source.t === 'adguard_home'
            "
            :positive-button-props="{ loading: refreshing }"
            @positive-click="force_refresh"
          >
            <template #trigger>
              <n-button size="small" type="primary" secondary>
                {{ t("geo_editor.item_card.force_refresh") }}
              </n-button>
            </template>
            {{ t("geo_editor.item_card.force_refresh_confirm") }}
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
