<script setup lang="ts">
import { refresh_geo_cache_key, search_geo_site_cache } from "@/api/geo/site";
import { QueryGeoKey } from "@/rust_bindings/common/geo";
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
  rules.value = await search_geo_site_cache(filter.value);
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
  <n-layout :native-scrollbar="false" content-style="padding: 10px;">
    <n-flex vertical>
      <n-flex :wrap="false">
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
        <GeoSiteNameSelect
          v-model:name="filter.name"
          @refresh="refresh"
        ></GeoSiteNameSelect>
        <GeoSiteKeySelect
          v-model:geo_key="filter.key"
          v-model:name="filter.name"
          @refresh="refresh"
        ></GeoSiteKeySelect>
      </n-flex>

      <!-- {{ rules }} -->
      <!-- <n-virtual-list :items="rules" :item-size="rules.length">
        <template #default="{ item }">
          <n-flex>
            <GeoSiteCacheCard :geo_site="item"></GeoSiteCacheCard
          ></n-flex>
        </template>
      </n-virtual-list> -->
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 900:3 1200:4 1600:5">
        <n-grid-item
          v-for="rule in rules"
          :key="rule.index"
          style="display: flex"
        >
          <GeoSiteCacheCard :geo_site="rule"></GeoSiteCacheCard>
        </n-grid-item>
      </n-grid>
    </n-flex>

    <GeoSiteDrawer
      @refresh:keys="refresh"
      v-model:show="show_geo_drawer_modal"
    ></GeoSiteDrawer>
  </n-layout>
</template>
