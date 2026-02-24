<script setup lang="ts">
import { refresh_geo_cache_key, search_geo_site_cache } from "@/api/geo/site";
import { sortGeoKeys } from "@/lib/geo_utils";
import type { QueryGeoKey } from "landscape-types/api/schemas";
import { onMounted, ref } from "vue";

const rules = ref<any>([]);

onMounted(async () => {
  await refresh();
});

const filter = ref<QueryGeoKey>({
  name: null,
  key: null,
});

async function refresh() {
  const result = await search_geo_site_cache(filter.value);
  rules.value = sortGeoKeys(result, filter.value.key || "");
}

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
</script>
<template>
  <n-flex style="flex: 1; overflow: hidden; margin-bottom: 10px" vertical>
    <n-flex style="width: 100%" :wrap="false">
      <!-- {{ filter }} -->
      <n-button @click="show_geo_drawer_modal = true">
        域名规则来源配置
      </n-button>
      <n-popconfirm
        :positive-button-props="{ loading: loading }"
        @positive-click="refresh_cache"
      >
        <template #trigger>
          <n-button>强制刷新</n-button>
        </template>
        强制刷新吗? 将会清空所有 key 并且重新下载
      </n-popconfirm>
      <GeoSiteKeySelect
        v-model:geo_key="filter.key"
        v-model:geo_name="filter.name"
        @refresh="refresh"
      ></GeoSiteKeySelect>
    </n-flex>

    <!-- <n-grid x-gap="12" y-gap="10" cols="1 600:2 900:3 1200:4 1600:5">
      <n-grid-item
        v-for="rule in rules"
        :key="rule.index"
        style="display: flex"
      >
        <GeoSiteCacheCard :geo_site="rule"></GeoSiteCacheCard>
      </n-grid-item>
    </n-grid> -->

    <n-virtual-list :item-size="52" :items="rules">
      <template #default="{ item }">
        <GeoSiteCacheCard :geo_site="item"></GeoSiteCacheCard>
      </template>
    </n-virtual-list>
    <GeoSiteDrawer @refresh:keys="refresh" v-model:show="show_geo_drawer_modal">
    </GeoSiteDrawer>
  </n-flex>
</template>
