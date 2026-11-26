<script setup lang="ts">
import { computed, ref, shallowRef, watch } from "vue";
import { useI18n } from "vue-i18n";
import type {
  GeoFileCacheKey,
  GeoSiteFileConfig,
  IpConfig,
} from "@landscape-router/types/api/schemas";
import { geoDatabases, type GeoKind } from "@/api/geo";
import { useFrontEndStore } from "@/stores/front_end_config";

type RuleValue = GeoSiteFileConfig | IpConfig;
const props = defineProps<{
  kind: GeoKind;
  entry: GeoFileCacheKey;
  matches?: RuleValue[];
}>();
const { t } = useI18n();
const frontend = useFrontEndStore();
const mode = ref<"matched" | "all">("matched");
const needsAll = computed(() => !props.matches || mode.value === "all");
const allRules = shallowRef<RuleValue[]>();
const loading = ref(false);
const failed = ref(false);
const retry = ref(0);
watch(
  [() => props.entry, needsAll, retry],
  async ([entry, all], previous, onCleanup) => {
    if (entry !== previous[0]) allRules.value = undefined;
    loading.value = false;
    failed.value = false;
    if (!all || allRules.value) return;
    const controller = new AbortController();
    onCleanup(() => controller.abort());
    loading.value = true;
    try {
      const result = await geoDatabases[props.kind].detail(
        entry,
        controller.signal,
      );
      if (!controller.signal.aborted) allRules.value = result.values;
    } catch {
      if (!controller.signal.aborted) failed.value = true;
    } finally {
      if (!controller.signal.aborted) loading.value = false;
    }
  },
  { immediate: true },
);
const rows = computed(() =>
  (needsAll.value ? allRules.value : props.matches)?.map((rule, index) => ({
    key: index,
    rule,
  })),
);
</script>
<template>
  <div class="geo-rule-details">
    <div class="entry-heading">
      <n-tag size="small" :bordered="false">{{
        frontend.MASK_INFO(entry.name)
      }}</n-tag>
      <strong>{{ frontend.MASK_INFO(entry.key) }}</strong>
    </div>
    <n-radio-group
      v-if="matches"
      v-model:value="mode"
      size="small"
      :aria-label="t('geo.detail_drawer.rule_details')"
    >
      <n-radio-button value="matched">{{
        t(`geo.geo_${kind}.matched_rules`)
      }}</n-radio-button>
      <n-radio-button value="all">{{
        t(`geo.geo_${kind}.all_rules`)
      }}</n-radio-button>
    </n-radio-group>
    <n-spin v-if="loading" />
    <n-empty v-else-if="failed" :description="t(`geo.geo_${kind}.load_failed`)">
      <template #extra
        ><n-button size="small" @click="retry++">{{
          t("common.retry")
        }}</n-button></template
      >
    </n-empty>
    <n-virtual-list
      v-else-if="rows?.length"
      :items="rows"
      :item-size="44"
      item-resizable
      class="rule-list"
    >
      <template #default="{ item }">
        <div class="rule-value">
          <template v-if="'match_type' in item.rule">
            <n-tag size="small" :bordered="false" type="info">{{
              item.rule.match_type
            }}</n-tag>
            <code>{{ frontend.MASK_INFO(item.rule.value) }}</code>
          </template>
          <code v-else
            >{{ frontend.MASK_INFO(item.rule.ip) }}/{{ item.rule.prefix }}</code
          >
        </div>
      </template>
    </n-virtual-list>
    <n-empty v-else :description="t(`geo.geo_${kind}.no_rules`)" />
  </div>
</template>
<style scoped>
.geo-rule-details {
  display: flex;
  flex-direction: column;
  gap: 12px;
  height: 100%;
  min-height: 0;
}
.entry-heading,
.rule-value {
  display: flex;
  align-items: baseline;
  gap: 8px;
}
.entry-heading {
  flex-wrap: wrap;
  overflow-wrap: anywhere;
}
.rule-list {
  flex: 1;
  min-height: 0;
}
.rule-value {
  box-sizing: border-box;
  min-height: 44px;
  padding: 8px 0;
  border-bottom: 1px solid var(--n-border-color);
}
.rule-value code {
  font-family: var(--font-mono);
  overflow-wrap: anywhere;
}
</style>
