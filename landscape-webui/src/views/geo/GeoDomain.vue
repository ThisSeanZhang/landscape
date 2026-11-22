<script setup lang="ts">
import { refresh_geo_cache_key, search_geo_site_cache } from "@/api/geo/site";
import { useGeoCachePage } from "@/composables/useGeoCachePage";
import { ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();
const {
  filter,
  rules,
  refresh,
  applyFilter,
  detailKey,
  showDetail,
  openDetail,
  closeDetail,
} = useGeoCachePage(search_geo_site_cache);

const loading = ref(false);
async function refresh_cache() {
  (async () => {
    loading.value = true;
    try {
      await refresh_geo_cache_key();
      await refresh();
    } finally {
      loading.value = false;
    }
  })();
}

const show_geo_drawer_modal = ref(false);
const show_lookup_modal = ref(false);
</script>
<template>
  <n-flex style="flex: 1; overflow: hidden; margin-bottom: 10px" vertical>
    <n-flex style="width: 100%" :wrap="false">
      <!-- {{ filter }} -->
      <n-button @click="show_geo_drawer_modal = true">
        {{ t("common.domain_rule_source_config") }}
      </n-button>
      <n-button @click="show_lookup_modal = true">
        {{ t("geo.lookup.site_action") }}
      </n-button>
      <n-popconfirm
        :positive-button-props="{ loading: loading }"
        @positive-click="refresh_cache"
      >
        <template #trigger>
          <n-button>{{ t("common.force_refresh") }}</n-button>
        </template>
        {{ t("common.force_refresh_confirm") }}
      </n-popconfirm>
      <GeoSiteKeySelect
        v-model:geo_key="filter.key"
        v-model:geo_name="filter.name"
        @refresh="applyFilter"
      ></GeoSiteKeySelect>
    </n-flex>

    <n-virtual-list :item-size="52" :items="rules">
      <template #default="{ item }">
        <GeoSiteCacheCard :geo_site="item" @details="openDetail" />
      </template>
    </n-virtual-list>
    <GeoSiteDetailDrawer
      v-if="detailKey"
      :geo_key="detailKey"
      :show="showDetail"
      @update:show="closeDetail"
    />
    <GeoSiteDrawer @refresh:keys="refresh" v-model:show="show_geo_drawer_modal">
    </GeoSiteDrawer>
    <GeoLookupModal mode="site" v-model:show="show_lookup_modal" />
  </n-flex>
</template>
