<script setup lang="ts">
import DnsRecordList from "@/components/dns/DnsRecordList.vue";
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
    <n-drawer-content closable :title="t('metric.dns.answer_details')">
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
      <DnsRecordList :records="query.records" />
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
.query-meta {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  color: v-bind("theme.textColor3");
  font-size: 12px;
}
</style>
