<script setup lang="ts">
import { useThemeVars } from "naive-ui";
import type { DnsAnswer } from "@/lib/metric/dnsAnswer";
import { useFrontEndStore } from "@/stores/front_end_config";

defineProps<{ records: DnsAnswer[] }>();
const frontend = useFrontEndStore();
const theme = useThemeVars();
</script>

<template>
  <ol class="records">
    <li v-for="(record, index) in records" :key="index">
      <div v-if="record.type" class="record-meta">
        <n-tag size="small" :bordered="false" type="info">{{
          record.type
        }}</n-tag>
        <span v-if="record.dnsClass">{{ record.dnsClass }}</span>
        <span class="ttl">TTL {{ record.ttl }} s</span>
      </div>
      <span v-if="record.name" class="record-name">{{
        frontend.MASK_INFO(record.name)
      }}</span>
      <code>{{ frontend.MASK_INFO(record.value) }}</code>
    </li>
  </ol>
</template>

<style scoped>
.record-meta {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  color: v-bind("theme.textColor3");
  font-size: 12px;
}
.records {
  margin: 0;
  padding: 0;
  list-style: none;
}
.records li {
  display: grid;
  gap: 6px;
  padding: 14px 0;
  border-top: 1px solid v-bind("theme.dividerColor");
  overflow-wrap: anywhere;
}
.ttl {
  margin-inline-start: auto;
}
.record-name {
  color: v-bind("theme.textColor3");
  font-size: 13px;
}
.records code {
  font-family: var(--font-mono);
  white-space: pre-wrap;
}
</style>
