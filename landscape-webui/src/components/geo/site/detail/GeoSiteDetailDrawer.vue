<script setup lang="ts">
import { get_geo_site_cache_detail } from "@/api/geo/site";
import type {
  GeoConfigKey,
  GeoDomainConfig,
} from "landscape-types/api/schemas";
import { onMounted, ref } from "vue";

const key = defineModel<GeoConfigKey>("geo_key", {
  required: true,
});
const show = defineModel<boolean>("show", { required: true });

const config = ref<GeoDomainConfig>();

async function refresh() {
  config.value = await get_geo_site_cache_detail(key.value);
}
</script>
<template>
  <n-drawer
    @after-enter="refresh"
    v-model:show="show"
    width="500px"
    placement="right"
  >
    <n-drawer-content title="规则细节" closable>
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
