<script setup lang="ts">
import { onMounted, ref } from "vue";

import { CountdownInst, CountdownProps } from "naive-ui";
import { SpinnerIos20Regular } from "@vicons/fluent";
import { PauseFilled, Renew } from "@vicons/carbon";

import { useFetchIntervalStore } from "@/stores/fetch_interval";

// import { Spinner } from "@vicons/fa";

const fetchIntervalStore = useFetchIntervalStore();

const countdownRef = ref<CountdownInst | null>();
onMounted(() => {
  fetchIntervalStore.SETTING_CALLBACK(() => {
    countdownRef.value?.reset();
  });
  fetchIntervalStore.IMMEDIATELY_EXECUTE();
});
const renderCountdown: CountdownProps["render"] = ({
  hours,
  minutes,
  seconds,
}) => {
  if (hours !== 0) {
    return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(
      2,
      "0"
    )}:${String(seconds).padStart(2, "0")}`;
  } else if (minutes !== 0) {
    return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(
      2,
      "0"
    )}`;
  } else if (minutes !== 0) {
    return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(
      2,
      "0"
    )}`;
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

function confirmChangeImterval() {
  fetchIntervalStore.interval_time = edit_interval.value;
  fetchIntervalStore.IMMEDIATELY_EXECUTE();
}
</script>

<template>
  <n-flex style="max-height: 24px; overflow: hidden" align="center">
    <n-popover @update:show="handleUpdateShow" trigger="hover">
      <template #trigger>
        <n-switch
          :round="!fetchIntervalStore.enable_interval"
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
        <n-input-group-label>设置刷新间隔 (ms):</n-input-group-label>
        <n-input-number
          style="width: 130px"
          :min="500"
          :max="50000"
          v-model:value="edit_interval"
          :step="500"
          button-placement="both"
        />
        <n-button @click="confirmChangeImterval" type="primary" ghost>
          确定
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
