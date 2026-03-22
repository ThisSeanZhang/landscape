<script setup lang="ts">
import { useIfaceNodeStore } from "@/stores/iface_node";
import {
  Add,
  FitToScreen,
  Locked,
  Unlocked,
  View,
  ViewOff,
} from "@vicons/carbon";
import { ref } from "vue";
import { useI18n } from "vue-i18n";

const emit = defineEmits(["fit-view"]);

const { t } = useI18n();
const show_create_dev = ref(false);
const ifaceNodeStore = useIfaceNodeStore();

function toggle_down_devices() {
  ifaceNodeStore.HIDE_DOWN(!ifaceNodeStore.hide_down_dev);
}
</script>

<template>
  <n-float-button-group
    shape="square"
    :left="20"
    :top="20"
    position="absolute"
    style="z-index: 6"
  >
    <n-float-button @click="show_create_dev = true">
      <n-icon><Add /></n-icon>
    </n-float-button>
    <n-float-button
      :aria-label="t('misc.topology.fit_view')"
      :title="t('misc.topology.fit_view')"
      @click="emit('fit-view')"
    >
      <n-icon><FitToScreen /></n-icon>
    </n-float-button>
    <n-float-button @click="toggle_down_devices">
      <n-icon>
        <View v-if="ifaceNodeStore.hide_down_dev" />
        <ViewOff v-else />
      </n-icon>
    </n-float-button>
    <n-float-button @click="ifaceNodeStore.TOGGLE_VIEW_LOCK">
      <n-icon>
        <Locked v-if="ifaceNodeStore.view_locked" />
        <Unlocked v-else />
      </n-icon>
    </n-float-button>
    <BridgeCreateModal v-model:show="show_create_dev" />
  </n-float-button-group>
</template>
