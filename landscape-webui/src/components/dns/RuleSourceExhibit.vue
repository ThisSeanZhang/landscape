<script lang="ts" setup>
import type { RuleSource } from "@landscape-router/types/api/schemas";
import { useI18n } from "vue-i18n";
import { useFrontEndStore } from "@/stores/front_end_config";

defineProps<{ source: RuleSource }>();
const { t } = useI18n();
const frontend = useFrontEndStore();
</script>

<template>
  <span class="rule-source">
    <n-tag
      size="small"
      :bordered="false"
      :type="source.t === 'geo_key' ? 'success' : 'info'"
    >
      {{
        source.t === "geo_key"
          ? "GeoSite"
          : t(`dns.rule_edit.source_style_${source.match_type}`)
      }}
    </n-tag>
    <code v-if="source.t === 'config'">{{
      frontend.MASK_INFO(source.value)
    }}</code>
    <code v-else
      >{{ frontend.MASK_INFO(source.name) }}/{{ frontend.MASK_INFO(source.key)
      }}<template v-if="source.attribute_key"
        >@{{ frontend.MASK_INFO(source.attribute_key) }}</template
      ></code
    >
    <n-tag
      v-if="source.t === 'geo_key' && source.inverse"
      size="small"
      type="warning"
      :bordered="false"
    >
      {{ t("common.inverse") }}
    </n-tag>
  </span>
</template>

<style scoped>
.rule-source {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 2px 6px;
  max-width: 100%;
}
.rule-source code {
  min-width: 0;
  font-family: var(--font-mono);
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}
</style>
