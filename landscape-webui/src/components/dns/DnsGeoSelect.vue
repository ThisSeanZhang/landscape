<script setup lang="ts">
import { ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { getGeoSiteAttributes } from "@landscape-router/types/api/geo-sites/geo-sites";
import GeoRuleKeySelect from "@/components/geo/GeoRuleKeySelect.vue";

const key = defineModel<string | null>("geo_key", { required: true });
const name = defineModel<string | null>("geo_name", { required: true });
const inverse = defineModel<boolean>("geo_inverse", { default: false });
const attribute = defineModel<string | null>("attr_key");
const { t } = useI18n();

const attributesOpen = ref(false);
const loading = ref(false);
const failed = ref(false);
const options = ref<{ label: string; value: string }[]>([]);
watch(
  [attributesOpen, name, key],
  async ([open, source, entry], _, onCleanup) => {
    options.value = [];
    failed.value = false;
    loading.value = false;
    if (!open || !source || !entry) return;

    const controller = new AbortController();
    const { signal } = controller;
    onCleanup(() => controller.abort());
    loading.value = true;
    try {
      const names = await getGeoSiteAttributes(
        { name: source, key: entry },
        { signal, silent: true },
      );
      if (!signal.aborted)
        options.value = names.map((value) => ({ label: value, value }));
    } catch {
      if (!signal.aborted) failed.value = true;
    } finally {
      if (!signal.aborted) loading.value = false;
    }
  },
);
</script>

<template>
  <n-flex class="geo-fields" :size="8" :wrap="false" align="center">
    <n-popover trigger="hover">
      <template #trigger>
        <n-checkbox
          v-model:checked="inverse"
          :aria-label="t('common.inverse')"
        />
      </template>
      {{ t("common.inverse") }}
    </n-popover>
    <n-input-group>
      <GeoRuleKeySelect
        kind="site"
        v-model:geo_key="key"
        v-model:geo_name="name"
        @change="attribute = null"
      />
      <n-select
        class="geo-attribute"
        v-model:value="attribute"
        v-model:show="attributesOpen"
        filterable
        clearable
        :disabled="!name || !key"
        :placeholder="t('common.filter_attr')"
        :options="options"
        :loading="loading"
      >
        <template v-if="failed" #empty>{{
          t("geo.common.search_failed")
        }}</template>
      </n-select>
    </n-input-group>
  </n-flex>
</template>

<style scoped>
.geo-fields {
  flex: 1;
  min-width: 0;
}
.geo-fields :deep(.n-input-group) {
  flex: 1;
  min-width: 0;
}
.geo-attribute {
  width: clamp(72px, 25%, 120px);
}
</style>
