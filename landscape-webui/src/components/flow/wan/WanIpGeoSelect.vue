<script setup lang="ts">
import { search_geo_ip_cache } from "@/api/geo/ip";
import { renderGeoSelectLabel, sortGeoKeys } from "@/lib/geo_utils";
import { GeoConfigKey } from "@/rust_bindings/common/geo";
import { computed, onMounted, ref } from "vue";

const geo_key = defineModel<string | null | undefined>("geo_key", {
  required: true,
});
const name = defineModel<string | null | undefined>("name", { required: true });

const loading = ref(false);

const keys = ref<GeoConfigKey[]>();

onMounted(async () => {
  await typing_key("");
});

let timer: NodeJS.Timeout | null = null;
async function handleSearch(query: string) {
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => {
    typing_key(query);
  }, 300);
}

async function typing_key(query: string) {
  try {
    loading.value = true;
    const result = await search_geo_ip_cache({
      name: name.value,
      key: query,
    });

    keys.value = sortGeoKeys(result, query);
  } finally {
    loading.value = false;
  }
}

const emit = defineEmits(["refresh"]);

// Bind a composite value to the Select to handle duplicate keys from different sources
const compositeValue = computed({
  get() {
    if (name.value && geo_key.value) {
      return `${name.value}###${geo_key.value}`;
    }
    return null;
  },
  set(val: string | null) {
    if (val) {
      const [n, k] = val.split("###");
      name.value = n;
      geo_key.value = k;
      emit("refresh");
    } else {
      clear();
    }
  },
});

const geo_key_options = computed(() => {
  let result = [];
  if (keys.value) {
    for (const each_key of keys.value) {
      result.push({
        label: each_key.key, // Display only the Key in the input box after selection
        value: `${each_key.name}###${each_key.key}`, // Unique value for identification
        data: each_key,
      });
    }
  }
  return result;
});

function clear() {
  geo_key.value = null;
  name.value = null; // Also clear the name when clearing the key
  emit("refresh");
  typing_key(""); // Reset list to default
}
</script>
<template>
  <n-select
    v-model:value="compositeValue"
    filterable
    placeholder="筛选key"
    :options="geo_key_options"
    :loading="loading"
    clearable
    remote
    :render-label="renderGeoSelectLabel"
    @clear="clear"
    @search="handleSearch"
    @focus="() => typing_key('')"
  />
</template>

