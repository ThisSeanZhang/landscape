<script setup lang="ts">
import { get_geo_site_configs } from "@/api/geo/site";
import { GeoSiteSourceConfig } from "@/rust_bindings/common/geo_site";
import { computed, onMounted, ref } from "vue";

const name = defineModel<string | null>("name", { required: true });

const loading = ref(false);

const configs = ref<GeoSiteSourceConfig[]>();

onMounted(async () => {
  await typing_key();
});

async function typing_key(query?: string) {
  try {
    loading.value = true;
    configs.value = await get_geo_site_configs(query);
  } finally {
    loading.value = false;
  }
}

const emit = defineEmits(["refresh"]);

const geo_name_options = computed(() => {
  let result = [];
  if (configs.value) {
    for (const config of configs.value) {
      result.push({
        label: config.name,
        value: config.name,
      });
    }
  }
  return result;
});
</script>
<template>
  <n-select
    v-model:value="name"
    filterable
    placeholder="选择 geo 名称"
    :options="geo_name_options"
    :loading="loading"
    clearable
    remote
    @update:value="emit('refresh')"
    @search="typing_key"
  />
</template>
