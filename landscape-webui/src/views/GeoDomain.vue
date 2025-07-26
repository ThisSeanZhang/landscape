<script setup lang="ts">
import { refresh_geo_cache_key, search_geo_site_cache } from "@/api/geo/site";
import { QueryGeoKey } from "@/rust_bindings/common/geo";
import { onMounted, ref } from "vue";

const rules = ref<any>([]);

// 添加加载状态
const loading = ref(false);
let refreshTimeout: number | null = null;

onMounted(async () => {
  await refreshWithDebounce();
});

const filter = ref<QueryGeoKey>({
  name: null,
  key: null,
});

// 防抖刷新函数
async function refreshWithDebounce() {
  if (refreshTimeout) {
    clearTimeout(refreshTimeout);
  }
  
  loading.value = true;
  // 延迟100ms执行更新，避免频繁请求
  refreshTimeout = window.setTimeout(async () => {
    try {
      rules.value = await search_geo_site_cache(filter.value);
    } finally {
      loading.value = false;
    }
  }, 100);
}

async function refresh() {
  await refreshWithDebounce();
}

async function refresh_cache() {
  (async () => {
    loading.value = true;
    try {
      await refresh_geo_cache_key();
      await refreshWithDebounce();
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
        <n-button @click="show_geo_drawer_modal = true" :disabled="loading">Geo 配置</n-button>
        <n-popconfirm
          :positive-button-props="{ loading: loading }"
          @positive-click="refresh_cache"
        >
          <template #trigger>
            <n-button :disabled="loading">强制刷新</n-button>
          </template>
          强制刷新吗? 将会清空所有 key 并且重新下载
        </n-popconfirm>
        <GeoSiteNameSelect
          v-model:name="filter.name"
          @refresh="refresh"
          :disabled="loading"
        ></GeoSiteNameSelect>
        <GeoSiteKeySelect
          v-model:geo_key="filter.key"
          v-model:name="filter.name"
          @refresh="refresh"
          :disabled="loading"
        ></GeoSiteKeySelect>
      </n-flex>

      <n-spin :show="loading">
        <!-- {{ rules }} -->
        <n-virtual-list 
          v-if="rules && rules.length > 0" 
          :item-height="150" 
          :items="rules" 
          style="flex: 1"
          height="100%"
        >
          <template #default="{ item }">
            <n-grid-item :key="item.index" style="display: flex; padding: 5px;">
              <GeoSiteCacheCard :geo_site="item"></GeoSiteCacheCard>
            </n-grid-item>
          </template>
        </n-virtual-list>
        
        <n-empty 
          v-else
          description="没有Geo数据"
          style="flex: 1; display: flex; align-items: center; justify-content: center; height: 200px;"
        />
      </n-spin>
    </n-flex>

    <GeoSiteDrawer
      @refresh:keys="refresh"
      v-model:show="show_geo_drawer_modal"
    ></GeoSiteDrawer>
  </n-layout>
</template>
