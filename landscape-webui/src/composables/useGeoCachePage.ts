import { computed, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import type {
  GeoFileCacheKey,
  QueryGeoKey,
} from "@landscape-router/types/api/schemas";
import { sortGeoKeys } from "@/lib/geo_utils";

export function useGeoCachePage(
  search: (filter: QueryGeoKey) => Promise<GeoFileCacheKey[]>,
) {
  const route = useRoute();
  const router = useRouter();
  const name = computed(() =>
    typeof route.query.name === "string" ? route.query.name : null,
  );
  const key = computed(() =>
    typeof route.query.key === "string" ? route.query.key : null,
  );
  const filter = ref({ name: name.value, key: key.value });
  const rules = ref<GeoFileCacheKey[]>([]);
  const detailKey = ref<GeoFileCacheKey>();
  const showDetail = ref(false);
  let latestSearch = 0;

  async function refresh() {
    const request = ++latestSearch;
    const query = { name: name.value, key: key.value };
    const matches = await search(query);
    if (request === latestSearch)
      rules.value = sortGeoKeys(matches, query.key ?? "");
  }

  watch(
    [name, key],
    ([name, key]) => {
      filter.value = { name, key };
      rules.value = [];
      showDetail.value = false;
      return refresh();
    },
    { immediate: true },
  );

  function applyFilter() {
    return router.replace({
      query: {
        ...route.query,
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

  function closeDetail() {
    showDetail.value = false;
    if (route.query.detail === "1") {
      return router.replace({ query: { ...route.query, detail: undefined } });
    }
  }

  return {
    filter,
    rules,
    refresh,
    applyFilter,
    detailKey,
    showDetail,
    openDetail,
    closeDetail,
  };
}
