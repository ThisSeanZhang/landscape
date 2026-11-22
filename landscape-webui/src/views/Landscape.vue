<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { useThemeVars } from "naive-ui";
import MobileInterfaceList from "@/components/topology/MobileInterfaceList.vue";
import { ChevronDown, ChevronUp } from "@vicons/carbon";
import { useMobileLayout } from "@/composables/useMobileLayout";
import CPUUsage from "@/components/sysinfo/CPUUsage.vue";
import MemUsage from "@/components/sysinfo/MemUsage.vue";
import DnsStatusCard from "@/components/dns/DnsStatusCard.vue";
import SystemInfo from "@/components/sysinfo/SystemInfo.vue";
import NetFlow from "@/components/topology/NetFlow.vue";

const { t } = useI18n();
const theme = useThemeVars();
const mapOpen = ref(false);
const mobile = useMobileLayout();
const showDetails = ref(false);
const compact = computed(() => mobile.value && !showDetails.value);
</script>

<template>
  <n-flex vertical :wrap="false" class="dashboard">
    <div v-if="mobile && showDetails" class="section-heading">
      <h2>{{ t("routes.dashboard") }}</h2>
      <n-button
        size="small"
        quaternary
        :aria-expanded="true"
        aria-controls="overview-cards"
        @click="showDetails = false"
      >
        {{ t("common.hide_details") }}
        <template #icon><n-icon :component="ChevronUp" /></template>
      </n-button>
    </div>
    <div id="overview-cards" class="overview" :class="{ compact }">
      <SystemInfo :compact="compact">
        <template #details>
          <n-button
            size="small"
            quaternary
            :aria-expanded="false"
            aria-controls="overview-cards"
            @click="showDetails = true"
          >
            {{ t("common.show_details") }}
            <template #icon><n-icon :component="ChevronDown" /></template>
          </n-button>
        </template>
      </SystemInfo>
      <CPUUsage :compact="compact" />
      <MemUsage :compact="compact" />
      <DnsStatusCard :compact="compact" />
    </div>

    <div v-if="mobile" class="section-heading network-heading">
      <h2>{{ t("topology.interfaces") }}</h2>
      <div
        class="view-switch"
        role="group"
        :aria-label="t('topology.interfaces')"
      >
        <button type="button" :aria-pressed="!mapOpen" @click="mapOpen = false">
          {{ t("topology.list_view") }}
        </button>
        <button type="button" :aria-pressed="mapOpen" @click="mapOpen = true">
          {{ t("topology.graph_view") }}
        </button>
      </div>
    </div>
    <n-divider v-else style="margin: 0" title-placement="left">{{
      t("common.topology_divider")
    }}</n-divider>
    <MobileInterfaceList v-if="mobile && !mapOpen" />
    <NetFlow v-else class="topology" />
  </n-flex>
</template>

<style scoped>
.dashboard {
  width: 100%;
  min-width: 0;
  container-type: inline-size;
}
.dashboard > .overview,
.dashboard > .section-heading {
  flex-shrink: 0;
}
.overview {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
.overview > * {
  min-height: 280px;
  min-width: 0;
}
@container (min-width: 1200px) {
  .overview {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }
}
@container (max-width: 599px) {
  .overview {
    grid-template-columns: minmax(0, 1fr);
  }
}
.overview.compact {
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0;
  border: 1px solid v-bind("theme.dividerColor");
  border-radius: 12px;
  background: v-bind("theme.cardColor");
  overflow: hidden;
}
.compact > * {
  min-height: 0;
}
.compact > :first-child {
  grid-column: 1 / -1;
}
.compact > .n-card {
  border: none;
  border-radius: 0;
}
.compact > .n-card + .n-card {
  border-inline-start: 1px solid v-bind("theme.dividerColor");
}
.compact :deep(.n-card-header) {
  padding: 12px 12px 4px;
}
.compact :deep(.n-card-header__main) {
  font-size: 13px;
}
.compact :deep(.n-card-content) {
  padding: 0 12px 14px !important;
}
.compact :deep(.overview-value) {
  display: block;
  font-size: clamp(18px, 5.4vw, 24px);
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  overflow-wrap: anywhere;
}
.compact :deep(.overview-meter) {
  height: 4px;
  margin-top: 8px;
  background: v-bind("theme.dividerColor");
  border-radius: 2px;
  overflow: hidden;
}
.compact :deep(.overview-meter span) {
  display: block;
  height: 100%;
  border-radius: inherit;
}
.section-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.section-heading h2 {
  margin: 0;
  font-size: 17px;
  font-weight: 600;
}
.network-heading {
  margin-top: 6px;
}
.view-switch {
  display: flex;
  border-radius: 7px;
  padding: 2px;
  border: 1px solid v-bind("theme.dividerColor");
}
.view-switch button {
  font: inherit;
  font-size: 13px;
  padding: 5px 12px;
  border-radius: 5px;
  border: none;
  background: transparent;
  color: v-bind("theme.textColor2");
  cursor: pointer;
}
.view-switch button[aria-pressed="true"] {
  background: color-mix(in srgb, currentColor 12%, transparent);
  color: v-bind("theme.primaryColor");
}
.topology {
  flex: 1;
  min-height: 550px;
  min-width: 0;
}
</style>
