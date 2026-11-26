<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import type { SelectOption } from "naive-ui";
import { searchGeoIpCache } from "@landscape-router/types/api/geo-ips/geo-ips";
import { searchGeoSiteCache } from "@landscape-router/types/api/geo-sites/geo-sites";
import type { GeoFileCacheKey } from "@landscape-router/types/api/schemas";
import { renderGeoSelectLabel } from "@/lib/geo_utils";

const { kind } = defineProps<{ kind: "site" | "ip" }>();
const name = defineModel<string | null>("geo_name", { required: true });
const key = defineModel<string | null>("geo_key", { required: true });
const emit = defineEmits<{ change: [] }>();
const { t } = useI18n();

const open = ref(false);
const query = ref("");
const loading = ref(false);
const failed = ref(false);
const matches = ref<GeoFileCacheKey[]>([]);
const limit = 30;

function optionFor(data: GeoFileCacheKey) {
  return {
    label: data.key,
    value: JSON.stringify([data.name, data.key]),
    data,
  };
}
const options = computed(() => matches.value.map(optionFor));
const selected = computed(() =>
  name.value && key.value
    ? optionFor({ name: name.value, key: key.value })
    : null,
);

function select(_value: string | null, option: SelectOption | null) {
  const entry = option?.data as GeoFileCacheKey | undefined;
  const nextName = entry?.name ?? "";
  const nextKey = entry?.key ?? "";
  if (name.value === nextName && key.value === nextKey) return;
  name.value = nextName;
  key.value = nextKey;
  emit("change");
}

function toggle(show: boolean) {
  open.value = show;
  if (!show) query.value = "";
}

watch([open, query, () => kind], ([show, q, type], _, onCleanup) => {
  matches.value = [];
  failed.value = false;
  loading.value = show;
  if (!show) return;

  const controller = new AbortController();
  const { signal } = controller;
  const timer = setTimeout(
    async () => {
      try {
        const search = type === "ip" ? searchGeoIpCache : searchGeoSiteCache;
        const result = await search({ q, limit }, { signal, silent: true });
        if (!signal.aborted) matches.value = result;
      } catch {
        if (!signal.aborted) failed.value = true;
      } finally {
        if (!signal.aborted) loading.value = false;
      }
    },
    q ? 250 : 0,
  );
  onCleanup(() => {
    clearTimeout(timer);
    controller.abort();
  });
});
</script>

<template>
  <n-select
    class="geo-rule-key"
    :value="selected?.value ?? null"
    :options="options"
    :fallback-option="selected ? () => selected! : false"
    :render-label="renderGeoSelectLabel"
    :placeholder="t('geo.common.search_key')"
    :loading="loading"
    filterable
    clearable
    remote
    @update:show="toggle"
    @update:value="select"
    @search="query = $event.trim()"
  >
    <template v-if="failed" #empty>{{
      t("geo.common.search_failed")
    }}</template>
    <template v-if="options.length === limit" #action>
      {{ t("geo.common.refine_search", { count: limit }) }}
    </template>
  </n-select>
</template>

<style scoped>
.geo-rule-key {
  flex: 1;
  min-width: 0;
}
</style>
