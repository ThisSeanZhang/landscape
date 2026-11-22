<script setup lang="ts">
import { computed } from "vue";
import type { CSSProperties } from "vue";
import { useI18n } from "vue-i18n";

defineOptions({ inheritAttrs: false });

const show = defineModel<boolean>("show", { required: true });
const enabled = defineModel<boolean>("enabled", { required: true });

const props = withDefaults(
  defineProps<{
    title: string;
    width?: string | number;
    maxHeight?: string;
    closable?: boolean;
    switchDisabled?: boolean;
  }>(),
  {
    width: "600px",
    closable: true,
    switchDisabled: false,
  },
);

const { t } = useI18n();

const cardStyle = computed<CSSProperties>(() => {
  const style: CSSProperties = {
    maxWidth: "calc(100% - 24px)",
    width: typeof props.width === "number" ? `${props.width}px` : props.width,
  };

  if (props.maxHeight) {
    style.maxHeight = props.maxHeight;
  }

  return style;
});

const headerStyle = computed<CSSProperties>(() => {
  const style: CSSProperties = {
    alignItems: "center",
    display: "flex",
    flexWrap: "wrap",
    gap: "8px",
  };

  if (props.closable) {
    style.paddingRight = "28px";
  }

  return style;
});

function closeModal() {
  show.value = false;
}
</script>

<template>
  <n-modal v-bind="$attrs" v-model:show="show" :auto-focus="false">
    <n-card
      :style="cardStyle"
      :bordered="false"
      :closable="closable"
      size="small"
      role="dialog"
      aria-modal="true"
      @close="closeModal"
    >
      <template #header>
        <div :style="headerStyle">
          <span>{{ title }}</span>
          <n-switch
            v-model:value="enabled"
            :disabled="switchDisabled"
            :aria-label="t('common.enable')"
          >
            <template #checked>{{ t("common.enable") }}</template>
            <template #unchecked>{{ t("common.disable") }}</template>
          </n-switch>
        </div>
      </template>

      <slot v-if="$slots.default" :enabled="enabled" :disabled="!enabled" />

      <template v-if="$slots.footer" #footer>
        <slot name="footer" :enabled="enabled" :disabled="!enabled" />
      </template>
    </n-card>
  </n-modal>
</template>
