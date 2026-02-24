<script lang="ts" setup>
import { computed } from "vue";
import type { FirewallBlacklistSource } from "@landscape-router/types/api/schemas";
import { useFrontEndStore } from "@/stores/front_end_config";

const frontEndStore = useFrontEndStore();

type Props = {
  source: FirewallBlacklistSource;
};

const props = defineProps<Props>();

const isBlockAll = computed(() => {
  if (props.source.t !== "config") return false;
  return (
    (props.source.ip === "0.0.0.0" || props.source.ip === "::") &&
    props.source.prefix === 0
  );
});
</script>

<template>
  <n-tooltip v-if="source.t === 'config' && isBlockAll">
    <template #trigger>
      <n-tag type="error">
        {{ frontEndStore.MASK_INFO(source.ip) }}/{{ source.prefix }}
      </n-tag>
    </template>
    将会阻止所有 IP 的访问
  </n-tooltip>
  <n-tag v-else-if="source.t === 'config'">
    {{ frontEndStore.MASK_INFO(source.ip) }}/{{ source.prefix }}
  </n-tag>
  <n-tag v-if="source.t === 'geo_key'" type="info">
    {{ frontEndStore.MASK_INFO(source.name) }}/{{
      frontEndStore.MASK_INFO(source.key)
    }}
  </n-tag>
</template>
