<script setup lang="ts">
import { get_geo_ip_configs, search_geo_ip_cache } from "@/api/geo/ip";
import { renderGeoSelectLabel, sortGeoKeys } from "@/lib/geo_utils";
import { GeoConfigKey } from "@/rust_bindings/common/geo";
import { GeoIpSourceConfig } from "@/rust_bindings/common/geo_ip";
import { computed, ref } from "vue";

const key = defineModel<string | null | undefined>("geo_key", {
  required: true,
});
const name = defineModel<string | null | undefined>("geo_name", {
  required: true,
});
const emit = defineEmits(["refresh"]);

const loading_key = ref(false);

// Use a composite value to handle duplicate keys from different sources
const compositeValue = computed({
  get() {
    if (name.value && key.value) {
      return `${name.value}###${key.value}`;
    }
    return null;
  },
  set(val: string | null) {
    if (val) {
      const [n, k] = val.split("###");
      name.value = n;
      key.value = k;
    } else {
      name.value = null;
      key.value = null;
    }
    // Only emit refresh when the value actually changes
  },
});

let searchTimer: NodeJS.Timeout | null = null;
function handleSearch(query: string) {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    typing_key(query);
  }, 300);
}

async function typing_key(query: string) {
  try {
    loading_key.value = true;
    const result = await search_geo_ip_cache({
      name: name.value,
      key: query,
    });

    keys.value = sortGeoKeys(result, query);
  } finally {
    loading_key.value = false;
  }
}

const keys = ref<GeoConfigKey[]>();
const geo_key_options = computed(() => {
  let result = [];
  if (keys.value) {
    for (const each_key of keys.value) {
      result.push({
        label: each_key.key,
        value: `${each_key.name}###${each_key.key}`,
        data: each_key,
      });
    }
  }
  return result;
});

const loading_name = ref(false);
const configs = ref<GeoIpSourceConfig[]>();

async function typing_name_key(query?: string) {
  try {
    loading_name.value = true;
    configs.value = await get_geo_ip_configs(query);
  } finally {
    loading_name.value = false;
  }
}

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

async function show_keys() {
  await typing_key("");
}

async function show_names() {
  await typing_name_key("");
}

// When name changes, reset key or refresh keys?
// Previous code called `update_key` on name change.
async function update_key() {
  key.value = null; // Clear key when name changes to avoid mismatch
  await typing_key("");
  emit("refresh");
}

function handleKeySelect() {
  emit("refresh");
}
</script>
<template>
  <n-input-group>
    <n-select
      :style="{ width: '33%' }"
      v-model:value="name"
      filterable
      placeholder="选择 geo 名称"
      :options="geo_name_options"
      :loading="loading_name"
      clearable
      remote
      @update:show="show_names"
      @update:value="update_key"
      @search="typing_name_key"
    />
    <n-select
      v-model:value="compositeValue"
      filterable
      placeholder="筛选key"
      :options="geo_key_options"
      :loading="loading_key"
      clearable
      remote
      :render-label="renderGeoSelectLabel"
      @update:show="show_keys"
      @update:value="handleKeySelect"
      @search="handleSearch"
      @focus="() => typing_key('')"
    />
  </n-input-group>
</template>

