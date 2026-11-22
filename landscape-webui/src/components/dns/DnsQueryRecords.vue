<script setup lang="ts">
import type { LandscapeRecord } from "@landscape-router/types/api/schemas";
import { useThemeVars } from "naive-ui";
import { shallowRef } from "vue";
import { useFrontEndStore } from "@/stores/front_end_config";

defineProps<{ records: LandscapeRecord[] }>();
const theme = useThemeVars();
const frontend = useFrontEndStore();
const expanded = shallowRef<LandscapeRecord>();
</script>

<template>
  <ol class="records">
    <li v-for="(record, index) in records" :key="index">
      <button
        type="button"
        class="record"
        :aria-expanded="expanded === record"
        @click="expanded = expanded === record ? undefined : record"
      >
        <span class="record-type">{{ record.rr_type }}</span>
        <span class="record-name">{{ frontend.MASK_INFO(record.name) }}</span>
        <code>{{ frontend.MASK_INFO(record.data) }}</code>
        <span class="ttl">TTL {{ record.ttl }} s</span>
      </button>
    </li>
  </ol>
</template>

<style scoped>
.records {
  margin: 0;
  padding: 0;
  list-style: none;
}
.records li {
  border-top: 1px solid v-bind("theme.dividerColor");
}
.record {
  display: flex;
  align-items: baseline;
  gap: 3px 6px;
  width: 100%;
  padding: 5px 0;
  border: 0;
  background: transparent;
  color: inherit;
  font: inherit;
  font-size: 13px;
  text-align: start;
  cursor: pointer;
}
.record:focus-visible {
  outline: 2px solid v-bind("theme.infoColor");
  outline-offset: -2px;
}
.record-type,
.ttl {
  flex: none;
  font-size: 11px;
  white-space: nowrap;
}
.record-type {
  padding: 1px 4px;
  border-radius: 3px;
  color: v-bind("theme.infoColor");
  background: color-mix(in srgb, currentColor 12%, transparent);
}
.ttl,
.record-name {
  color: v-bind("theme.textColor2");
}
.ttl {
  font-variant-numeric: tabular-nums;
}
.record-name,
code {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.record-name {
  max-width: 32%;
}
code {
  flex: 1;
  font-family: var(--font-mono);
}
.record[aria-expanded="true"] {
  flex-wrap: wrap;
}
.record[aria-expanded="true"] .record-name {
  flex: 1;
  max-width: none;
  white-space: normal;
  overflow-wrap: anywhere;
}
.record[aria-expanded="true"] code {
  order: 1;
  flex: 0 0 100%;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
</style>
