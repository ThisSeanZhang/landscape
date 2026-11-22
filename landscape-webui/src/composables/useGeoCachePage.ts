import { computed, ref, shallowRef, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import type {
  GeoFileCacheKey,
  GeoSiteLookupResult,
  GeoIpLookupResult,
} from "@landscape-router/types/api/schemas";
import { geoDatabases, type GeoKind } from "@/api/geo";
import { sortGeoKeys } from "@/lib/geo_utils";

export function useGeoCachePage(kind: GeoKind) {
  const database = geoDatabases[kind];
  const route = useRoute();
  const router = useRouter();
  const name = computed(() =>
    typeof route.query.name === "string" ? route.query.name : null,
  );
  const key = computed(() =>
    typeof route.query.key === "string" ? route.query.key : null,
  );
  const lookupValue = computed(() => {
    const value = route.query[database.lookupParam];
    return typeof value === "string" ? value.trim() : "";
  });
  const filter = ref({ name: name.value, key: key.value });
  const keys = shallowRef<GeoFileCacheKey[]>([]);
  const hits = shallowRef<(GeoSiteLookupResult | GeoIpLookupResult)[]>([]);
  const lookupKeys = computed(() =>
    lookupValue.value ? hits.value.map((hit) => hit.key) : undefined,
  );
  const rules = computed(() => {
    if (!lookupKeys.value) return keys.value;
    const term = key.value?.toUpperCase() ?? "";
    const matching = lookupKeys.value.filter(
      (entry) =>
        (!name.value || entry.name === name.value) &&
        entry.key.toUpperCase().includes(term),
    );
    return sortGeoKeys(matching, term);
  });
  const detailKey = shallowRef<GeoFileCacheKey>();
  const showDetail = ref(false);
  const loading = ref(false);
  const failed = ref(false);
  let latestSearch = 0;

  // A reverse lookup returns every matching key. Narrow that result locally.
  const query = computed(() =>
    lookupValue.value
      ? { lookup: lookupValue.value }
      : { name: name.value, key: key.value },
  );
  async function refresh() {
    const request = ++latestSearch;
    loading.value = true;
    failed.value = false;
    try {
      const params = query.value;
      if (params.lookup) {
        const result = await database.lookup(params.lookup);
        if (request === latestSearch) hits.value = result;
      } else {
        const result = await database.search({
          name: params.name,
          key: params.key,
        });
        if (request === latestSearch)
          keys.value = sortGeoKeys(result, params.key ?? "");
      }
    } catch {
      if (request === latestSearch) failed.value = true;
    } finally {
      if (request === latestSearch) loading.value = false;
    }
  }

  watch(
    query,
    () => {
      keys.value = [];
      hits.value = [];
      return refresh();
    },
    { immediate: true },
  );
  watch([name, key, lookupValue], () => {
    filter.value = { name: name.value, key: key.value };
    showDetail.value = false;
  });

  function applyFilter(nextValue = lookupValue.value) {
    return router.replace({
      query: {
        ...route.query,
        [database.lookupParam]: nextValue || undefined,
        name: filter.value.name || undefined,
        key: filter.value.key || undefined,
        detail: undefined,
      },
    });
  }

  function openDetail(entry: GeoFileCacheKey) {
    detailKey.value = entry;
    showDetail.value = true;
  }
  const linkedDetail = computed(() => {
    if (route.query.detail !== "1" || !name.value || !key.value) return;
    const target = key.value.toUpperCase();
    return rules.value.find(
      (entry) =>
        entry.name === name.value && entry.key.toUpperCase() === target,
    );
  });
  watch(linkedDetail, (entry) => {
    if (entry) openDetail(entry);
    else showDetail.value = false;
  });
  watch(rules, (entries) => {
    const current = detailKey.value;
    if (!showDetail.value || !current) return;
    const selected = entries.find(
      (entry) => entry.name === current.name && entry.key === current.key,
    );
    if (selected) detailKey.value = selected;
    else showDetail.value = false;
  });

  function closeDetail() {
    showDetail.value = false;
    if (route.query.detail === "1") {
      return router.replace({ query: { ...route.query, detail: undefined } });
    }
  }

  const matchedValues = computed(
    () =>
      hits.value.find(
        (hit) =>
          hit.key.name === detailKey.value?.name &&
          hit.key.key === detailKey.value?.key,
      )?.values,
  );
  return {
    filter,
    rules,
    lookupValue,
    lookupKeys,
    matchedValues,
    loading,
    failed,
    refresh,
    applyFilter,
    detailKey,
    showDetail,
    openDetail,
    closeDetail,
  };
}
