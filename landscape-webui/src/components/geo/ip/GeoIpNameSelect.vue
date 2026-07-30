<script setup lang="ts">
import { get_geo_ip_configs } from "@/api/geo/ip";
import type { GeoIpSourceConfig } from "@landscape-router/types/api/schemas";
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
const { t } = useI18n();

const name = defineModel<string | null>("name", { required: true });

const loading = ref(false);

const configs = ref<GeoIpSourceConfig[]>();

onMounted(async () => {
  await typing_key();
});

async function typing_key(query?: string) {
  try {
    loading.value = true;
    configs.value = await get_geo_ip_configs(query);
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
    :placeholder="t('geo.geo_ip_name_select.select_geo_ip_name')"
    :options="geo_name_options"
    :loading="loading"
    clearable
    remote
    @update:value="emit('refresh')"
    @search="typing_key"
  />
</template>
