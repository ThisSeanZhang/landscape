<script setup lang="ts">
import {
  get_geo_site_cache_detail,
  get_geo_site_configs,
  search_geo_site_cache,
} from "@/api/geo/site";
import { renderGeoSelectLabel, sortGeoKeys } from "@/lib/geo_utils";
import { GeoConfigKey } from "@/rust_bindings/common/geo";
import { GeoSiteSourceConfig } from "@/rust_bindings/common/geo_site";
import { computed, onMounted, ref } from "vue";

const key = defineModel<string | null | undefined>("geo_key", {
  required: true,
});
const name = defineModel<string | null | undefined>("geo_name", {
  required: true,
});
const inverse = defineModel<boolean>("geo_inverse", {
  default: false,
});

const attribute_key = defineModel<string | null>("attr_key");

const emit = defineEmits(["refresh"]);

const loading_name = ref(false);
const loading_key = ref(false);
const loading_attrs = ref(false);

onMounted(async () => {
  await typing_name_key("");
  await typing_key("");
  await typing_attribute(name.value, key.value);
});

const configs = ref<GeoSiteSourceConfig[]>();
async function typing_name_key(query?: string) {
  try {
    loading_name.value = true;
    configs.value = await get_geo_site_configs(query);
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
    const result = await search_geo_site_cache({
      name: name.value,
      key: query,
    });

    keys.value = sortGeoKeys(result, query);
  } finally {
    loading_key.value = false;
  }
}

const keys = ref<GeoConfigKey[]>();

// Composite value logic
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
      // Also reset attribute when key changes
      attribute_key.value = null;
    } else {
      name.value = ""; // Assuming empty string as per defineModel type might be string
      key.value = "";
      attribute_key.value = null;
    }
  },
});

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

async function handleKeySelect() {
  // name and key are already set by compositeValue
  if (name.value && key.value) {
    await typing_attribute(name.value, key.value);
  }
}

const attributes = ref<Set<string> | null>(null);
async function typing_attribute(n: string, k: string) {
  if (!(n && k)) {
    return;
  }

  try {
    loading_attrs.value = true;
    let config = await get_geo_site_cache_detail({
      name: n,
      key: k,
    });
    attributes.value = new Set(
      config.values.flatMap((value) => value.attributes)
    );
  } finally {
    loading_attrs.value = false;
  }
}

const attribute_options = computed(() => {
  let result = [];
  if (attributes.value) {
    for (const each_key of attributes.value) {
      result.push({
        label: each_key,
        value: each_key,
      });
    }
  }
  return result;
});
</script>
<template>
  <n-flex :size="[10, 0]" :wrap="false" align="center">
    <n-popover trigger="hover">
      <template #trigger>
        <n-checkbox v-model:checked="inverse"> </n-checkbox>
      </template>
      <span>反选 </span>
    </n-popover>
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
        @update:value="emit('refresh')"
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
        @update:value="handleKeySelect"
        @search="handleSearch"
        @focus="() => typing_key('')"
      />

      <n-select
        :style="{ width: '120px' }"
        v-model:value="attribute_key"
        filterable
        placeholder="筛选 attr"
        :options="attribute_options"
        :loading="loading_attrs"
        clearable
      />
    </n-input-group>
  </n-flex>
</template>
