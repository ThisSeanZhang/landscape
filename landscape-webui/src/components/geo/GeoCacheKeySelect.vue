<script setup lang="ts">
import { geoDatabases, type GeoKind } from "@/api/geo";
import { renderGeoSelectLabel, sortGeoKeys } from "@/lib/geo_utils";
import type { GeoFileCacheKey } from "@landscape-router/types/api/schemas";
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";

const props = defineProps<{ kind: GeoKind; lookupKeys?: GeoFileCacheKey[] }>();
const key = defineModel<string | null>("geo_key", {
  required: true,
  default: null,
});
const name = defineModel<string | null>("geo_name", {
  required: true,
  default: null,
});
const { t } = useI18n();
const emit = defineEmits(["refresh"]);

const loading_key = ref(false);

// Use a composite value to handle duplicate keys from different sources
const compositeValue = computed({
  get() {
    if (key.value) {
      return JSON.stringify([name.value, key.value]);
    }
    return null;
  },
  set(val: string | null) {
    if (val) {
      const [n, k] = JSON.parse(val);
      name.value = n;
      key.value = k;
    } else {
      key.value = null;
    }
    // Only emit refresh when the value actually changes
  },
});

let searchTimer: ReturnType<typeof setTimeout> | null = null;
function handleSearch(query: string) {
  if (props.lookupKeys) return;
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    typing_key(query);
  }, 300);
}

async function typing_key(query: string) {
  if (props.lookupKeys) return;
  try {
    loading_key.value = true;
    const result = await geoDatabases[props.kind].search({
      name: name.value,
      key: query,
    });

    keys.value = sortGeoKeys(result, query);
  } finally {
    loading_key.value = false;
  }
}

const keys = ref<GeoFileCacheKey[]>();
const geo_key_options = computed(() => {
  let result = [];
  const entries =
    props.lookupKeys?.filter(
      (entry) => !name.value || entry.name === name.value,
    ) ?? keys.value;
  if (entries) {
    for (const each_key of entries) {
      result.push({
        label: each_key.key,
        value: JSON.stringify([each_key.name, each_key.key]),
        data: each_key,
      });
    }
  }
  return result;
});

const loading_name = ref(false);
const sourceNames = ref<string[]>([]);

async function typing_name_key(query?: string) {
  if (props.lookupKeys) return;
  try {
    loading_name.value = true;
    const configs = await geoDatabases[props.kind].listSources(query);
    sourceNames.value = configs.map((config) => config.name);
  } finally {
    loading_name.value = false;
  }
}

const geo_name_options = computed(() => {
  const names = props.lookupKeys
    ? [...new Set(props.lookupKeys.map((entry) => entry.name))].sort()
    : sourceNames.value;
  return names.map((value) => ({ value, label: value }));
});

async function show_keys() {
  await typing_key("");
}

async function show_names() {
  await typing_name_key("");
}

function update_key() {
  key.value = null; // Clear key when name changes to avoid mismatch
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
      :input-props="{ 'aria-label': t('common.select_geo_name') }"
      :placeholder="t('common.select_geo_name')"
      :options="geo_name_options"
      :loading="loading_name"
      clearable
      :remote="!lookupKeys"
      @update:show="(open: boolean) => open && show_names()"
      @update:value="update_key"
      @search="typing_name_key"
    />
    <n-select
      v-model:value="compositeValue"
      filterable
      :input-props="{ 'aria-label': t('common.filter_key') }"
      :placeholder="t('common.filter_key')"
      :options="geo_key_options"
      :loading="loading_key"
      clearable
      :remote="!lookupKeys"
      :fallback-option="
        (value: string | number) => ({ value, label: key ?? '' })
      "
      :render-label="renderGeoSelectLabel"
      @update:show="(open: boolean) => open && show_keys()"
      @update:value="handleKeySelect"
      @search="handleSearch"
    />
  </n-input-group>
</template>
