<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { ArrowUpRight } from "@vicons/carbon";
import { LayersOutline } from "@vicons/ionicons5";
import type { GeoFileCacheKey } from "@landscape-router/types/api/schemas";
import type { GeoKind } from "@/api/geo";
import { useFrontEndStore } from "@/stores/front_end_config";

const { target } = defineProps<{
  target: { kind: GeoKind; entry: GeoFileCacheKey } | { ip: string };
}>();
const frontend = useFrontEndStore();
const { t } = useI18n();
const link = computed(() => {
  if ("ip" in target) {
    return {
      to: { name: "routes.geo-ip", query: { ip: target.ip } },
      label: t("geo.geo_ip.lookup_address", {
        ip: frontend.MASK_INFO(target.ip),
      }),
      icon: LayersOutline,
    };
  }
  const { name, key } = target.entry;
  return {
    to: {
      name: target.kind === "ip" ? "routes.geo-ip" : "routes.geo-domain",
      query: { name, key, detail: "1" },
    },
    label: t(`geo.geo_${target.kind}.view_key`, {
      name: frontend.MASK_INFO(name),
      key: frontend.MASK_INFO(key),
    }),
    icon: ArrowUpRight,
  };
});
</script>

<template>
  <RouterLink
    class="geo-rule-link"
    :to="link.to"
    :aria-label="link.label"
    :title="link.label"
  >
    <n-icon :component="link.icon" aria-hidden="true" />
    <slot />
  </RouterLink>
</template>

<style scoped>
.geo-rule-link {
  display: inline-flex;
  align-self: center;
  align-items: center;
  justify-content: center;
  min-width: 1.5em;
  min-height: 1.5em;
  border-radius: 4px;
  color: var(--accent, currentColor);
}
.geo-rule-link:hover,
.geo-rule-link:focus-visible {
  background-color: color-mix(in srgb, currentColor 12%, transparent);
}
</style>
