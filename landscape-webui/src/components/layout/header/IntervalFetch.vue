<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";

import { CountdownInst, CountdownProps } from "naive-ui";
import { SpinnerIos20Regular } from "@vicons/fluent";
import { PauseFilled } from "@vicons/carbon";
import { useI18n } from "vue-i18n";

import { useFetchIntervalStore } from "@/stores/fetch_interval";

// import { Spinner } from "@vicons/fa";

const fetchIntervalStore = useFetchIntervalStore();
const { t } = useI18n();

const countdownRef = ref<CountdownInst | null>();
onMounted(() => {
  fetchIntervalStore.start(() => {
    countdownRef.value?.reset();
  });
});

onUnmounted(() => {
  fetchIntervalStore.stop();
});

const renderCountdown: CountdownProps["render"] = ({
  hours,
  minutes,
  seconds,
}) => {
  if (hours !== 0) {
    return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(
      2,
      "0",
    )}:${String(seconds).padStart(2, "0")}`;
  } else if (minutes !== 0) {
    return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
  } else if (minutes !== 0) {
    return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
  } else if (seconds != 0) {
    return `${String(seconds).padStart(2, "0")}`;
  } else {
    return `00`;
  }
};

const edit_interval = ref(fetchIntervalStore.interval_time);

function handleUpdateShow() {
  edit_interval.value = fetchIntervalStore.interval_time;
}

function confirmInterval() {
  if (edit_interval.value == null) return;
  fetchIntervalStore.interval_time = edit_interval.value;
  fetchIntervalStore.refreshNow();
}
</script>

<template>
  <n-flex style="max-height: 24px; overflow: hidden" align="center">
    <n-button
      v-if="fetchIntervalStore.error_message !== undefined"
      size="tiny"
      type="warning"
      secondary
      @click="fetchIntervalStore.refreshNow()"
    >
      {{ t("common.refresh_paused") }}
    </n-button>
    <n-popover v-else @update:show="handleUpdateShow" trigger="hover">
      <template #trigger>
        <n-switch
          :aria-label="t('common.auto_refresh')"
          :round="fetchIntervalStore.enable_interval"
          v-model:value="fetchIntervalStore.enable_interval"
        >
          <template #checked-icon>
            <n-icon class="element" size="20">
              <SpinnerIos20Regular />
            </n-icon>
          </template>
          <template #unchecked-icon>
            <n-icon size="20">
              <PauseFilled />
            </n-icon>
          </template>
          <template #checked>
            <n-countdown
              :render="renderCountdown"
              ref="countdownRef"
              :duration="fetchIntervalStore.interval_time"
              :active="fetchIntervalStore.enable_interval"
            />
          </template>
        </n-switch>
      </template>

      <n-input-group>
        <n-input-group-label>{{
          t("common.refresh_interval_ms")
        }}</n-input-group-label>
        <n-input-number
          style="width: 130px"
          :min="500"
          :max="50000"
          v-model:value="edit_interval"
          :step="500"
          button-placement="both"
        />
        <n-button @click="confirmInterval" type="primary" ghost>
          {{ t("common.confirm") }}
        </n-button>
      </n-input-group>
    </n-popover>

    <!-- <n-icon
      @click="fetchIntervalStore.enable_interval = false"
      v-if="fetchIntervalStore.enable_interval"
      class="element"
      size="20"
    >
      <SpinnerIos20Regular />
    </n-icon>
    <n-icon @click="fetchIntervalStore.enable_interval = true" v-else size="20">
      <PauseFilled />
    </n-icon> -->
  </n-flex>
</template>

<style scoped>
.element {
  animation: rotateAnimation 5s linear infinite;
  /* animation: rotateAnimation 5s cubic-bezier(0.25, 0.1, 0.25, 1) infinite; */
}

@keyframes rotateAnimation {
  from {
    transform: rotate(0deg); /* 初始角度为 0 度 */
  }
  to {
    transform: rotate(360deg); /* 最终角度为 360 度 */
  }
}
</style>
