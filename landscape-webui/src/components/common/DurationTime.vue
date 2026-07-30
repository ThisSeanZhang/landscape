<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";

type DurationUnit = "second" | "minute" | "hour" | "day";
type DurationStyle = "compact" | "detailed";

function formatDuration(
  durationSeconds: number,
  unitLabel: (unit: DurationUnit, value: number) => string,
  style: DurationStyle = "compact",
  separator = " ",
): string {
  const totalSeconds = Number.isFinite(durationSeconds)
    ? Math.max(0, Math.floor(durationSeconds))
    : 0;
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (style === "detailed") {
    const parts: string[] = [];

    if (days > 0) parts.push(`${days}${unitLabel("day", days)}`);
    if (hours > 0) parts.push(`${hours}${unitLabel("hour", hours)}`);
    if (minutes > 0) {
      parts.push(`${minutes}${unitLabel("minute", minutes)}`);
    }
    if (seconds > 0 || parts.length === 0) {
      parts.push(`${seconds}${unitLabel("second", seconds)}`);
    }

    return parts.join(separator);
  }

  if (totalSeconds < 60) {
    return `${seconds}${unitLabel("second", seconds)}`;
  }

  if (totalSeconds < 3600) {
    return `${minutes}${unitLabel("minute", minutes)} ${seconds}${unitLabel("second", seconds)}`;
  }

  if (totalSeconds < 86400) {
    return `${hours}${unitLabel("hour", hours)} ${minutes}${unitLabel("minute", minutes)}`;
  }

  return `${days}${unitLabel("day", days)} ${hours}${unitLabel("hour", hours)}`;
}

interface Props {
  seconds: number;
  mode?: DurationStyle;
}

const props = withDefaults(defineProps<Props>(), {
  mode: "compact",
});

const { t, locale } = useI18n();

function unitLabel(unit: DurationUnit, value: number): string {
  if (props.mode === "detailed") {
    const plural = value === 1 ? "" : "_plural";
    return t(`common.${unit}_full${plural}`);
  }

  return t(`common.${unit}`);
}

const separator = computed(() =>
  props.mode === "detailed" && locale.value.startsWith("zh") ? "" : " ",
);

const formatted = computed(() =>
  formatDuration(props.seconds, unitLabel, props.mode, separator.value),
);
</script>

<template>
  <span>{{ formatted }}</span>
</template>
