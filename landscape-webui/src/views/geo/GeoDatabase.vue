<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useThemeVars } from "naive-ui";
import { useI18n } from "vue-i18n";
import { geoDatabases, type GeoKind } from "@/api/geo";
import { useGeoCachePage } from "@/composables/useGeoCachePage";
import { useMobileLayout } from "@/composables/useMobileLayout";
import GeoRuleDetails from "@/components/geo/GeoRuleDetails.vue";

const { kind } = defineProps<{ kind: GeoKind }>();

const { t } = useI18n();
const theme = useThemeVars();
const mobile = useMobileLayout();
const {
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
} = useGeoCachePage(kind);

const lookupInput = ref("");
watch(
  lookupValue,
  (value) => {
    lookupInput.value = value;
  },
  { immediate: true },
);
const selectedId = computed(() =>
  showDetail.value && detailKey.value
    ? JSON.stringify([detailKey.value.name, detailKey.value.key])
    : undefined,
);
const rows = computed(() =>
  rules.value.map((entry) => ({
    key: JSON.stringify([entry.name, entry.key]),
    entry,
  })),
);
function setLookup(value: string) {
  lookupInput.value = value;
  if (lookupValue.value === value) return refresh();
  return applyFilter(value);
}
function submitLookup() {
  const raw = lookupInput.value.trim();
  if (kind === "ip" || !raw) return setLookup(raw);
  const host = raw
    .replace(/^[a-z][a-z\d+.-]*:\/\//i, "")
    .split(/[/?#]/)[0]
    .replace(/:\d+$/, "")
    .trim()
    .toLowerCase();
  if (host) return setLookup(host);
}

const refreshingCache = ref(false);
async function refreshCache() {
  refreshingCache.value = true;
  try {
    await geoDatabases[kind].refresh();
    await refresh();
  } finally {
    refreshingCache.value = false;
  }
}
const showSources = ref(false);
</script>
<template>
  <div class="geo-page">
    <div class="toolbar">
      <n-button @click="showSources = true">{{
        t(
          kind === "ip"
            ? "common.ip_rule_source_config"
            : "common.domain_rule_source_config",
        )
      }}</n-button>
      <n-popconfirm
        :positive-button-props="{ loading: refreshingCache }"
        @positive-click="refreshCache"
      >
        <template #trigger
          ><n-button>{{ t("common.force_refresh") }}</n-button></template
        >
        {{
          t(
            kind === "ip"
              ? "common.force_refresh_confirm_long"
              : "common.force_refresh_confirm",
          )
        }}
      </n-popconfirm>
    </div>
    <form
      class="filters"
      :aria-label="t('common.filters')"
      @submit.prevent="submitLookup"
    >
      <GeoCacheKeySelect
        :kind="kind"
        v-model:geo_key="filter.key"
        v-model:geo_name="filter.name"
        :lookup-keys="lookupKeys"
        @refresh="applyFilter()"
      />
      <n-input-group>
        <n-input
          v-model:value="lookupInput"
          clearable
          :input-props="{ 'aria-label': t(`geo.lookup.${kind}_action`) }"
          :placeholder="t(`geo.lookup.${kind}_placeholder`)"
          @clear="setLookup('')"
        />
        <n-button attr-type="submit" secondary type="primary">{{
          t(`geo.lookup.${kind}_action`)
        }}</n-button>
      </n-input-group>
    </form>
    <div class="panes">
      <section class="pane" :aria-label="t(`geo.geo_${kind}.entries`)">
        <h2 class="pane-header">
          {{ t(`geo.geo_${kind}.entries`) }}
          <span v-if="!loading && !failed">{{ rows.length }}</span>
        </h2>
        <div v-if="loading" class="pane-state"><n-spin /></div>
        <n-empty
          v-else-if="failed"
          class="pane-state"
          :description="t(`geo.geo_${kind}.load_failed`)"
        >
          <template #extra
            ><n-button size="small" @click="refresh">{{
              t("common.retry")
            }}</n-button></template
          >
        </n-empty>
        <n-empty
          v-else-if="!rows.length"
          class="pane-state"
          :description="t('geo.lookup.no_result')"
        >
          <template
            v-if="
              kind === 'site' &&
              lookupValue &&
              !lookupValue.includes('.') &&
              !lookupKeys?.length
            "
            #extra
          >
            <n-button size="small" @click="setLookup(lookupValue + '.com')">{{
              t("geo.lookup.domain_notice_positive", {
                domain: lookupValue + ".com",
              })
            }}</n-button>
          </template>
        </n-empty>
        <n-virtual-list v-else :items="rows" :item-size="48" class="entry-list">
          <template #default="{ item }">
            <GeoCacheEntry
              :kind="kind"
              :entry="item.entry"
              :selected="selectedId === item.key"
              @details="openDetail"
            />
          </template>
        </n-virtual-list>
      </section>
      <section
        v-if="!mobile"
        class="pane"
        :aria-label="t('geo.detail_drawer.rule_details')"
      >
        <div class="pane-header">
          <h2>{{ t("geo.detail_drawer.rule_details") }}</h2>
          <n-button
            v-if="showDetail"
            size="tiny"
            quaternary
            @click="closeDetail"
            >{{ t("common.close") }}</n-button
          >
        </div>
        <GeoRuleDetails
          :kind="kind"
          v-if="showDetail && detailKey"
          class="details"
          :key="selectedId"
          :entry="detailKey"
          :matches="matchedValues"
        />
        <n-empty
          v-else
          class="pane-state"
          :description="t(`geo.geo_${kind}.select_entry`)"
        />
      </section>
    </div>
    <n-drawer
      v-if="mobile"
      :show="showDetail"
      placement="right"
      @update:show="closeDetail"
    >
      <n-drawer-content
        :title="t('geo.detail_drawer.rule_details')"
        closable
        body-content-style="height: 100%; box-sizing: border-box"
      >
        <GeoRuleDetails
          :kind="kind"
          v-if="showDetail && detailKey"
          :key="selectedId"
          :entry="detailKey"
          :matches="matchedValues"
        />
      </n-drawer-content>
    </n-drawer>
    <GeoIpDrawer
      v-if="kind === 'ip'"
      v-model:show="showSources"
      @refresh:keys="refresh"
    />
    <GeoSiteDrawer v-else v-model:show="showSources" @refresh:keys="refresh" />
  </div>
</template>
<style scoped>
.geo-page {
  flex: 1;
  min-width: 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 12px;
}
.toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.filters {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr));
  gap: 10px;
}
.filters > * {
  min-width: 0;
}
.panes {
  flex: 1;
  min-height: 0;
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(0, 3fr);
  gap: 12px;
}
.pane {
  display: flex;
  flex-direction: column;
  min-height: 0;
  min-width: 0;
  overflow: hidden;
  background: v-bind("theme.cardColor");
  border: 1px solid v-bind("theme.borderColor");
  border-radius: 6px;
}
.pane-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  min-height: 24px;
  border-bottom: 1px solid v-bind("theme.dividerColor");
}
h2 {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
}
.pane-header span {
  color: v-bind("theme.textColor3");
  font-weight: 400;
  font-variant-numeric: tabular-nums;
}
.pane-header .n-button {
  margin-inline-start: auto;
}
.pane-state {
  margin: auto;
  padding: 12px;
  text-align: center;
}
.entry-list,
.details {
  flex: 1;
  min-height: 0;
}
.details {
  padding: 12px;
}
@media (max-width: 768px) {
  .panes {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
