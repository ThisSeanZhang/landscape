<script setup lang="ts">
import { refresh_geo_cache_key, search_geo_ip_cache } from "@/api/geo/ip";
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
} = useGeoCachePage(search_geo_ip_cache);

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
    <n-flex :wrap="false">
      <!-- {{ filter }} -->
      <n-button @click="show_geo_drawer_modal = true">
        {{ t("common.ip_rule_source_config") }}
      </n-button>
      <n-button @click="show_lookup_modal = true">
        {{ t("geo.lookup.ip_action") }}
      </n-button>
      <n-popconfirm
        :positive-button-props="{ loading: loading }"
        @positive-click="refresh_cache"
      >
        <template #trigger>
          <n-button>{{ t("common.force_refresh") }}</n-button>
        </template>
        {{ t("common.force_refresh_confirm_long") }}
      </n-popconfirm>

      <GeoIpKeySelect
        v-model:geo_key="filter.key"
        v-model:geo_name="filter.name"
        @refresh="applyFilter"
      ></GeoIpKeySelect>
    </n-flex>

    <n-virtual-list :item-size="52" :items="rules">
      <template #default="{ item }">
        <GeoIpCacheCard :geo_site="item" @details="openDetail" />
      </template>
    </n-virtual-list>
    <GeoIpDetailDrawer
      v-if="detailKey"
      :geo_key="detailKey"
      :show="showDetail"
      @update:show="closeDetail"
    />
    <GeoIpDrawer
      @refresh:keys="refresh"
      v-model:show="show_geo_drawer_modal"
    ></GeoIpDrawer>
    <GeoLookupModal mode="ip" v-model:show="show_lookup_modal" />
  </n-flex>
</template>
