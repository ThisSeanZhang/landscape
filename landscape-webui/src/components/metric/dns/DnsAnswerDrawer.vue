<script setup lang="ts">
import { CopyOutline } from "@vicons/ionicons5";
import { useMessage, useThemeVars } from "naive-ui";
import { useI18n } from "vue-i18n";
import { copy_context_to_clipboard } from "@/lib/common";
import type { DnsLogEntry } from "@/lib/metric/dnsAnswer";
import { useFrontEndStore } from "@/stores/front_end_config";
import { usePreferenceStore } from "@/stores/preference";

defineProps<{ query: DnsLogEntry }>();
const show = defineModel<boolean>("show", { required: true });
const { t } = useI18n();
const message = useMessage();
const theme = useThemeVars();
const frontend = useFrontEndStore();
const prefs = usePreferenceStore();
</script>

<template>
  <n-drawer
    v-model:show="show"
    placement="right"
    width="min(460px, 100%)"
    :aria-label="t('metric.dns.answer_details')"
  >
    <n-drawer-content
      closable
      :title="t('metric.dns.answer_details')"
      :style="{
        '--answer-muted': theme.textColor3,
        '--answer-divider': theme.dividerColor,
        '--answer-font': theme.fontFamilyMono,
      }"
    >
      <h2>{{ frontend.MASK_INFO(query.domain) }}</h2>
      <div class="query-meta">
        <n-tag size="small" :bordered="false">{{ query.query_type }}</n-tag>
        <span>{{ query.response_code }}</span>
        <n-time
          :time="query.report_time"
          type="datetime"
          :time-zone="prefs.timezone"
        />
      </div>
      <h3>
        {{ t("metric.dns.answer_count", { count: query.records.length }) }}
      </h3>
      <ol class="records">
        <li v-for="(record, index) in query.records" :key="index">
          <div v-if="record.type" class="record-meta">
            <n-tag size="small" :bordered="false" type="info">{{
              record.type
            }}</n-tag>
            <span>{{ record.dnsClass }}</span>
            <span class="ttl">TTL {{ record.ttl }} s</span>
          </div>
          <span v-if="record.name" class="record-name">{{
            frontend.MASK_INFO(record.name)
          }}</span>
          <code>{{ frontend.MASK_INFO(record.value) }}</code>
        </li>
      </ol>
      <template v-if="!frontend.presentation_mode" #footer>
        <n-button
          size="small"
          secondary
          @click="copy_context_to_clipboard(message, query.answers.join('\n'))"
        >
          <template #icon><n-icon :component="CopyOutline" /></template>
          {{ t("metric.dns.copy_answers") }}
        </n-button>
      </template>
    </n-drawer-content>
  </n-drawer>
</template>

<style scoped>
h2 {
  margin: 0 0 8px;
  overflow-wrap: anywhere;
  font-size: 19px;
}
h3 {
  margin: 24px 0 6px;
  font-size: 13px;
}
.query-meta,
.record-meta {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  color: var(--answer-muted);
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
  border-top: 1px solid var(--answer-divider);
  overflow-wrap: anywhere;
}
.ttl {
  margin-inline-start: auto;
}
.record-name {
  color: var(--answer-muted);
  font-size: 13px;
}
.records code {
  font-family: var(--answer-font);
  white-space: pre-wrap;
}
</style>
