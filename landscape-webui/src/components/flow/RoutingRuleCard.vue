<script setup lang="ts" generic="Source">
import { computed, useId } from "vue";
import { useI18n } from "vue-i18n";
import { useThemeVars } from "naive-ui";

const { enabled, sources } = defineProps<{
  title: string;
  enabled: boolean;
  priority: number;
  sources: Source[];
  deleteRule: () => Promise<void>;
}>();
const emit = defineEmits<{ edit: [] }>();
const { t } = useI18n();
const theme = useThemeVars();
const titleId = useId();
const matchesHeadingId = useId();
const statusLabel = computed(() =>
  t(enabled ? "flow.rule_card.enabled" : "common.disabled"),
);
</script>

<template>
  <n-card
    size="small"
    tag="article"
    :aria-labelledby="titleId"
    class="routing-rule"
    content-style="padding: 0"
  >
    <header class="rule-heading">
      <div class="rule-title-row">
        <n-tooltip trigger="click">
          <template #trigger>
            <button
              type="button"
              class="rule-status"
              :class="{ enabled }"
              :aria-label="statusLabel"
              :title="statusLabel"
            ></button>
          </template>
          {{ statusLabel }}
        </n-tooltip>
        <h3 :id="titleId">{{ title }}</h3>
        <div class="rule-actions">
          <n-button size="small" secondary type="warning" @click="emit('edit')">
            {{ t("common.edit") }}
          </n-button>
          <n-popconfirm @positive-click="deleteRule">
            <template #trigger>
              <n-button size="small" tertiary type="error">
                {{ t("common.delete") }}
              </n-button>
            </template>
            {{ t("common.confirm_delete") }}
          </n-popconfirm>
        </div>
      </div>
      <div class="rule-routing">
        <span class="priority"
          >{{ t("common.priority") }} <strong>{{ priority }}</strong></span
        >
        <slot name="summary" />
      </div>
    </header>
    <slot />
    <div class="matches">
      <h4 :id="matchesHeadingId">
        {{ t("flow.rule_card.match_rules", { count: sources.length }) }}
      </h4>
      <n-scrollbar v-if="sources.length" class="source-scroll" trigger="none">
        <ul
          class="rule-sources"
          tabindex="0"
          :aria-labelledby="matchesHeadingId"
        >
          <li v-for="(source, index) in sources" :key="index">
            <slot name="source" :source="source" />
          </li>
        </ul>
      </n-scrollbar>
      <slot v-else name="empty" />
    </div>
    <slot name="footer" />
  </n-card>
</template>

<style scoped>
.routing-rule {
  --accent: v-bind("theme.infoColor");
  --muted: v-bind("theme.textColor2");
  min-width: 0;
  overflow-wrap: anywhere;
  border-radius: 8px;
}
.rule-heading {
  display: grid;
  gap: 8px;
  padding: 12px;
  border-radius: 8px 8px 0 0;
  border-bottom: 1px solid var(--n-border-color);
  background: linear-gradient(
    110deg,
    color-mix(in srgb, var(--accent) 14%, transparent),
    transparent
  );
}
.rule-title-row {
  display: grid;
  grid-template-columns: 8px minmax(0, 1fr) auto;
  align-items: baseline;
  gap: 8px;
}
.rule-title-row h3 {
  margin: 0;
  font-size: 16px;
  line-height: 1.4;
}
.rule-status {
  display: grid;
  place-items: center;
  align-self: start;
  width: 24px;
  height: 28px;
  margin-inline: -8px;
  padding: 0;
  border: 0;
  border-radius: 4px;
  background: transparent;
  cursor: help;
}
.rule-status:focus-visible {
  outline: 2px solid var(--accent);
}
.rule-status::before {
  content: "";
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: v-bind("theme.textColor3");
}
.rule-status.enabled::before {
  background-color: v-bind("theme.successColor");
}
.rule-routing {
  display: flex;
  align-items: baseline;
  gap: 8px;
}
.priority {
  flex: none;
  padding: 1px 6px;
  border-radius: 4px;
  background: color-mix(in srgb, var(--accent) 15%, var(--n-color));
  color: color-mix(in srgb, var(--accent) 60%, var(--n-text-color));
  font-size: 12px;
}
.priority strong {
  font-family: var(--font-mono);
}
.matches {
  --match-inset: 12px;
  --match-row-height: 2em;
  --match-gap: 6px;
  display: grid;
  justify-items: start;
  gap: 4px;
  margin: 0 var(--match-inset) 12px;
  border-top: 1px solid var(--n-border-color);
  padding-top: 8px;
}
.matches h4 {
  margin: 0 0 4px;
  color: var(--muted);
  font-weight: 500;
  font-size: 12px;
}
.matches :deep(.source-scroll) {
  justify-self: stretch;
  min-width: 0;
  width: calc(100% + var(--match-inset));
  max-height: calc(2.5 * var(--match-row-height) + 2 * var(--match-gap));
}
.matches :deep(.source-scroll:has(:focus-visible)) {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
.rule-sources {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-start;
  gap: var(--match-gap) 4px;
  margin: 0;
  padding: 0;
  padding-inline-end: var(--match-inset);
  list-style: none;
  outline: none;
}
.rule-sources > li {
  box-sizing: border-box;
  min-height: var(--match-row-height);
  max-width: 100%;
  padding: 2px 4px;
  border: 1px solid var(--n-border-color);
  border-radius: 6px;
}
.rule-sources :deep(code) {
  font-size: 13px;
}
.rule-actions {
  display: flex;
  flex: none;
  gap: 6px;
}
.rule-heading + .matches {
  border-top: 0;
  padding-top: 10px;
}
</style>
