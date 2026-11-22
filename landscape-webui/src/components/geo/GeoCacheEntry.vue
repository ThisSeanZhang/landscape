<script setup lang="ts">
import type { GeoFileCacheKey } from "@landscape-router/types/api/schemas";
import type { GeoKind } from "@/api/geo";
import { ChevronForward } from "@vicons/ionicons5";
import { useThemeVars } from "naive-ui";
import { useI18n } from "vue-i18n";
import { useFrontEndStore } from "@/stores/front_end_config";

defineProps<{ kind: GeoKind; entry: GeoFileCacheKey; selected: boolean }>();
const emit = defineEmits<{ details: [entry: GeoFileCacheKey] }>();
const { t } = useI18n();
const theme = useThemeVars();
const frontend = useFrontEndStore();
</script>
<template>
  <button
    type="button"
    class="geo-entry"
    :aria-pressed="selected"
    :aria-label="
      t(`geo.geo_${kind}.view_key`, {
        name: frontend.MASK_INFO(entry.name),
        key: frontend.MASK_INFO(entry.key),
      })
    "
    @click="emit('details', entry)"
  >
    <span class="source" :title="frontend.MASK_INFO(entry.name)">{{
      frontend.MASK_INFO(entry.name)
    }}</span>
    <strong :title="frontend.MASK_INFO(entry.key)">{{
      frontend.MASK_INFO(entry.key)
    }}</strong>
    <n-icon :component="ChevronForward" aria-hidden="true" />
  </button>
</template>
<style scoped>
.geo-entry {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  height: 48px;
  padding: 0 12px;
  border: 0;
  border-bottom: 1px solid v-bind("theme.dividerColor");
  background: transparent;
  color: inherit;
  font: inherit;
  text-align: start;
  cursor: pointer;
}
.geo-entry:hover {
  background: v-bind("theme.hoverColor");
}
.geo-entry:focus-visible {
  outline: 2px solid v-bind("theme.primaryColor");
  outline-offset: -2px;
}
.geo-entry[aria-pressed="true"] {
  background: color-mix(in srgb, v-bind("theme.primaryColor") 10%, transparent);
  box-shadow: inset 3px 0 v-bind("theme.primaryColor");
}
.source,
strong {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.source {
  max-width: 45%;
  border-radius: 4px;
  padding: 1px 6px;
  background: v-bind("theme.tagColor");
  color: v-bind("theme.textColor2");
  font-size: 12px;
}
strong {
  flex: 1;
  font-weight: 500;
}
.geo-entry .n-icon {
  color: v-bind("theme.textColor3");
}
</style>
