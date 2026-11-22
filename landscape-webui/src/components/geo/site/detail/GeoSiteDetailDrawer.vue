<script setup lang="ts">
import { get_geo_site_cache_detail } from "@/api/geo/site";
import type {
  GeoFileCacheKey,
  GeoDomainConfig,
} from "@landscape-router/types/api/schemas";
import { ref, watch } from "vue";
import { useI18n } from "vue-i18n";
const { t } = useI18n();

const props = defineProps<{ geo_key: GeoFileCacheKey }>();
const show = defineModel<boolean>("show", { required: true });

const config = ref<GeoDomainConfig>();

watch(
  () => (show.value ? props.geo_key : null),
  async (entry, _, onCleanup) => {
    if (!entry) return;
    let current = true;
    onCleanup(() => {
      current = false;
    });
    config.value = undefined;
    const result = await get_geo_site_cache_detail(entry);
    if (current) config.value = result;
  },
  { immediate: true },
);
</script>
<template>
  <n-drawer v-model:show="show" width="500px" placement="right">
    <n-drawer-content :title="t('geo.detail_drawer.rule_details')" closable>
      <n-virtual-list v-if="config" :item-size="110" :items="config.values">
        <template #default="{ item }">
          <n-card style="margin: 5px 0px" :title="item.value" size="small">
            <n-tag :bordered="false" type="info">
              {{ item.match_type }}
            </n-tag>
          </n-card>
        </template>
      </n-virtual-list>
    </n-drawer-content>
  </n-drawer>
</template>
