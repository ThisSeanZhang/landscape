<script lang="ts" setup>
import { useThemeVars } from "naive-ui";
import { DotMark } from "@vicons/carbon";
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { usePreferenceStore } from "@/stores/preference";

const { t } = useI18n();
const prefStore = usePreferenceStore();
const themeVars = ref(useThemeVars());

interface Props {
  /** 24 liveness buckets, oldest first. */
  presence: boolean[];
  /** Epoch milliseconds of the last ARP reply, if any. */
  lastSeen?: number;
}

const props = withDefaults(defineProps<Props>(), { lastSeen: undefined });

const total = computed(() => props.presence.length || 24);
const onlineCount = computed(() => props.presence.filter(Boolean).length);

const summary = computed(() => {
  if (!props.lastSeen) return t("lan_device.presence_none");
  return t("lan_device.presence_summary", {
    seen: onlineCount.value,
    total: total.value,
  });
});
</script>

<template>
  <n-tooltip trigger="hover">
    <template #trigger>
      <div class="dots">
        <n-icon
          v-for="(enable, idx) in presence"
          :key="idx"
          :color="enable ? themeVars.successColor : ''"
          size="12"
        >
          <DotMark />
        </n-icon>
      </div>
    </template>
    <div>{{ summary }}</div>
    <div v-if="lastSeen">
      {{ t("lan_device.arp_last_seen") }}:
      <n-time :time="lastSeen" :time-zone="prefStore.timezone" />
    </div>
  </n-tooltip>
</template>

<style scoped>
.dots {
  display: grid;
  grid-template-columns: repeat(12, max-content);
  justify-content: center;
  gap: 2px 3px;
}
</style>
