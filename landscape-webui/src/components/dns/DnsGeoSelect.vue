<script setup lang="ts">
import {
  get_geo_site_cache_detail,
  get_geo_site_configs,
  search_geo_site_cache,
} from "@/api/geo/site";
import { GeoConfigKey } from "@/rust_bindings/common/geo";
import { GeoSiteSourceConfig } from "@/rust_bindings/common/geo_site";
import { computed, onMounted, ref } from "vue";

const key = defineModel<string>("geo_key", {
  required: true,
});
const name = defineModel<string>("geo_name", {
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

async function typing_key(query: string) {
  try {
    loading_key.value = true;
    keys.value = await search_geo_site_cache({
      name: name.value,
      key: query,
    });
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
        label: `${each_key.key}-${each_key.name}`,
        value: each_key.key,
        data: each_key,
      });
    }
  }
  return result;
});

async function select_key(value: string, option: any) {
  key.value = value;
  name.value = option.data.name;
  attribute_key.value = null;
  await typing_attribute(option.data.name, value);
}

const attributes = ref<Set<string> | null>(null);
async function typing_attribute(name: string, key: string) {
  if (!(name && key)) {
    return;
  }

  try {
    loading_attrs.value = true;
    let config = await get_geo_site_cache_detail({
      name,
      key,
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
  <n-flex :wrap="false" align="center">
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
        v-model:value="key"
        filterable
        placeholder="筛选key"
        :options="geo_key_options"
        :loading="loading_key"
        clearable
        remote
        @update:value="select_key"
        @search="typing_key"
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
