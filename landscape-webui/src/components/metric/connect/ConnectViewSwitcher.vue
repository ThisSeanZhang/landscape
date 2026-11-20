<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";
import { useThemeVars } from "naive-ui";
import { PulseOutline, TimeOutline } from "@vicons/ionicons5";
import { useCapabilityStore } from "@/stores/capability";

const route = useRoute();
const theme = useThemeVars();
const capability = useCapabilityStore();
const sections = [
  {
    label: "switcher.connections",
    live: "routes.connect-live",
    history: "routes.connect-history",
  },
  { label: "col.iface", live: "routes.connect-iface", history: null },
  {
    label: "filter.src_ip",
    live: "routes.connect-src",
    history: "routes.connect-history-src",
  },
  {
    label: "filter.dst_ip",
    live: "routes.connect-dst",
    history: "routes.connect-history-dst",
  },
] as const;
const current = computed(
  () =>
    sections.find(
      (section) =>
        section.live === route.name || section.history === route.name,
    ) ?? sections[0],
);
const history = computed(() => route.name === current.value.history);
const views = computed(() =>
  sections.flatMap((section) => {
    const name = history.value ? section.history : section.live;
    return name ? [{ name, label: section.label }] : [];
  }),
);
</script>

<template>
  <nav class="connect-switcher" :aria-label="$t('metric.connect.title')">
    <div class="modes">
      <RouterLink :to="{ name: current.live, query: route.query }">
        <n-icon :component="PulseOutline" aria-hidden="true" />
        {{ $t("metric.connect.switcher.live") }}
      </RouterLink>
      <RouterLink
        v-if="capability.HAS('metric_persistent')"
        :to="{
          name: current.history ?? sections[0].history,
          query: route.query,
        }"
      >
        <n-icon :component="TimeOutline" aria-hidden="true" />
        {{ $t("metric.connect.switcher.history") }}
      </RouterLink>
    </div>
    <div class="sections">
      <RouterLink
        v-for="view in views"
        :key="view.name"
        :to="{ name: view.name, query: route.query }"
      >
        {{ $t(`metric.connect.${view.label}`) }}
      </RouterLink>
    </div>
  </nav>
</template>

<style scoped>
.connect-switcher,
.modes,
.sections {
  display: flex;
  align-items: center;
}
.connect-switcher,
.sections {
  flex-wrap: wrap;
}
.connect-switcher {
  gap: 6px 12px;
}
.modes {
  gap: 2px;
  padding: 3px;
  border: 1px solid v-bind("theme.dividerColor");
  border-radius: 10px;
  background: v-bind("theme.cardColor");
}
.connect-switcher a {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 10px;
  line-height: 20px;
  border-radius: 6px;
  color: v-bind("theme.textColor2");
  text-decoration: none;
  white-space: nowrap;
}
.connect-switcher a:hover {
  background: v-bind("theme.hoverColor");
}
.connect-switcher a:focus-visible {
  outline: 2px solid v-bind("theme.primaryColor");
}
.connect-switcher a[aria-current="page"] {
  color: v-bind("theme.primaryColor");
  font-weight: 600;
}
.modes a[aria-current="page"] {
  background: color-mix(in srgb, v-bind("theme.primaryColor") 14%, transparent);
}
.sections a[aria-current="page"] {
  text-decoration: underline;
  text-underline-offset: 5px;
}
</style>
